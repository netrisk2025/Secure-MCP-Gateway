package edge

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// progressPerSecond is CP-21: at most this many progress notifications per
// second are forwarded for one request (FR-1.40).
const progressPerSecond = 10

// progressFixedClock, when non-zero, is the Unix nanosecond time the rate
// bound uses instead of the clock (tests).
var progressFixedClock atomic.Int64

func progressNow() time.Time {
	if n := progressFixedClock.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Now()
}

// progressRelay carries the progress notifications of one tools/call to
// the harness: the Approval Service's keep-alives while the call is held
// (FR-3.19) and the backend's own progress while it runs (FR-1.39). Every
// notification uses the northbound progress token and a progress value
// greater than the last one sent. Backend progress messages pass the
// response filters before relay (SR-5.9-1): a blocked message is dropped,
// a transformed one is relayed as transformed, and each relayed
// notification carries provenance with the filters applied and any tags
// (FR-4.17). After stop, nothing more is relayed (FR-1.40).
//
// The backend's reader hands notifications over without waiting: they are
// queued (at most progressQueue) and a worker filters and sends them, so a
// slow harness or filter cannot stall an instance that other calls share.
// stop sends what is queued, then ends the relay; the dispatcher has
// handed over every notification the server wrote before its response
// by the time the call returns.
type progressRelay struct {
	g    *Gateway
	ctx  context.Context
	req  *mcp.CallToolRequest
	call *pipeline.Call
	tok  any
	hw   *heldWriter

	mu      sync.Mutex
	last    float64
	window  time.Time
	inWin   int
	stopped bool

	qmu     sync.Mutex
	queue   chan *mcp.ProgressNotificationParams
	drained chan struct{}
	closed  bool
}

// progressQueue bounds the notifications waiting for the worker; more are
// dropped, as the rate bound would drop them anyway.
const progressQueue = 4 * progressPerSecond

func (g *Gateway) newProgress(ctx context.Context, req *mcp.CallToolRequest, call *pipeline.Call) *progressRelay {
	hw, _ := ctx.Value(ctxHeld).(*heldWriter)
	p := &progressRelay{g: g, ctx: ctx, req: req, call: call, hw: hw}
	if req != nil && req.Params != nil {
		p.tok = req.Params.GetProgressToken()
	}
	return p
}

// enabled reports whether the request asked for progress.
func (p *progressRelay) enabled() bool {
	return p != nil && p.tok != nil && p.req != nil && p.req.Session != nil
}

// keepAlive sends one approval keep-alive as progress (FR-3.19). It
// reports false when the request carries no progress token.
func (p *progressRelay) keepAlive(msg string) bool {
	if !p.enabled() {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return true
	}
	p.last++
	if err := p.req.Session.NotifyProgress(p.ctx, &mcp.ProgressNotificationParams{ProgressToken: p.tok, Progress: p.last, Message: msg}); err != nil {
		p.g.log.Debug("progress keep-alive failed", "err", err)
	}
	return true
}

// relay queues one backend progress notification. The backend saw a
// Gateway-issued token; the harness sees its own.
func (p *progressRelay) relay(n *mcp.ProgressNotificationParams) {
	if !p.enabled() || n == nil {
		return
	}
	p.qmu.Lock()
	defer p.qmu.Unlock()
	if p.closed {
		return
	}
	if p.queue == nil {
		p.queue, p.drained = make(chan *mcp.ProgressNotificationParams, progressQueue), make(chan struct{})
		go func() {
			defer close(p.drained)
			for n := range p.queue {
				p.forward(n)
			}
		}()
	}
	select {
	case p.queue <- n:
	default:
	}
}

// forward filters and sends one notification.
func (p *progressRelay) forward(n *mcp.ProgressNotificationParams) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || n.Progress <= p.last { // FR-1.39: strictly increasing
		return
	}
	now := progressNow()
	if now.Sub(p.window) >= time.Second {
		p.window, p.inWin = now, 0
	}
	if p.inWin >= progressPerSecond { // FR-1.40, CP-21
		return
	}
	msg, meta, ok := p.inspect(n.Message)
	if !ok {
		return
	}
	p.inWin++
	p.last = n.Progress
	if p.hw != nil {
		p.hw.startStream()
	}
	if err := p.req.Session.NotifyProgress(p.ctx, &mcp.ProgressNotificationParams{Meta: meta, ProgressToken: p.tok,
		Progress: n.Progress, Total: n.Total, Message: msg}); err != nil {
		p.g.log.Debug("progress relay failed", "err", err)
	}
}

// stop sends the queued notifications and ends the relay. It is safe to
// call more than once.
func (p *progressRelay) stop() {
	if p == nil {
		return
	}
	p.qmu.Lock()
	if !p.closed {
		p.closed = true
		if p.queue != nil {
			close(p.queue)
		}
	}
	drained := p.drained
	p.qmu.Unlock()
	if drained != nil {
		<-drained
	}
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
}

// inspect runs the response filters over a progress message. It reports
// false when a filter blocks the message.
func (p *progressRelay) inspect(msg string) (string, mcp.Meta, bool) {
	prov := map[string]any{"serverId": p.call.Server, "serverRevision": p.call.ServerRevision, "toolRevision": p.call.ToolRevision,
		"decisionId": p.call.DecisionID, "untrusted": true}
	if msg == "" {
		prov["filters"] = []string{}
		return "", mcp.Meta{metaPrefix + "provenance": prov}, true
	}
	pc := *p.call
	pc.Inspection, pc.OutputSchema = nil, nil // a separate inspection; a message has no structured content
	res, applied, v := p.g.filters.RunResponse(p.ctx, &pc, &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: msg}}})
	if v != nil {
		p.g.log.Warn("backend progress message withheld by the response filters", "correlation", p.call.CorrelationID, "reason", v.ReasonCode)
		return "", nil, false
	}
	var b strings.Builder
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	if applied == nil {
		applied = []string{}
	}
	prov["filters"] = applied
	prov["disposition"] = pc.Inspection.Disposition()
	if tags := pc.Inspection.Tags(); len(tags) > 0 {
		prov["tags"] = tags
	}
	return b.String(), mcp.Meta{metaPrefix + "provenance": prov}, true
}
