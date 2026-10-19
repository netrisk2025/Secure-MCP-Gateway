package consoleapi

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Bounds of the journal browser.
const (
	DefaultPageSize = 100
	MaxPageSize     = 500 // FR-7.3
	MaxExportEvents = 100000
	streamKeepAlive = 15 * time.Second
	streamBuffer    = 64
	// maxStreams bounds concurrent evidence streams; each holds a
	// goroutine and a buffer for as long as the client keeps it open.
	maxStreams = 32
)

// eventFilter selects journal events. Every set field must match.
type eventFilter struct {
	class, phase, origin, outcome, reason, session, correlation, principal, decision string
	server, tool, rule, revision                                                     string
	text                                                                             string
	since, until                                                                     time.Time
}

func parseFilter(r *http.Request) (eventFilter, error) {
	q := r.URL.Query()
	f := eventFilter{class: q.Get("class"), phase: q.Get("phase"), origin: q.Get("origin"), outcome: q.Get("outcome"), reason: q.Get("reason_code"),
		session: q.Get("session_id"), correlation: q.Get("correlation_id"), principal: q.Get("principal_id"), decision: q.Get("decision_id"),
		server: q.Get("server"), tool: q.Get("tool"), rule: q.Get("rule"), revision: q.Get("policy_revision"),
		text: strings.ToLower(q.Get("q"))}
	for name, dst := range map[string]*time.Time{"since": &f.since, "until": &f.until} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return f, fmt.Errorf("%s must be an RFC 3339 time", name)
			}
			*dst = t
		}
	}
	return f, nil
}

func eq(want, got string) bool { return want == "" || want == got }

func (f eventFilter) match(e audit.Event) bool {
	if !eq(f.class, e.Class) || !eq(f.phase, string(e.Phase)) || !eq(f.origin, e.Origin) || !eq(f.outcome, e.Outcome) || !eq(f.reason, e.ReasonCode) ||
		!eq(f.session, e.SessionID) || !eq(f.correlation, e.CorrelationID) || !eq(f.principal, e.PrincipalID) || !eq(f.decision, e.DecisionID) {
		return false
	}
	if !eq(f.revision, e.PolicyRevision) {
		return false
	}
	detail, _ := e.Detail.(map[string]any)
	if f.server != "" && e.ServerRevision != f.server && fmt.Sprint(detail["server"]) != f.server {
		return false
	}
	if f.tool != "" && e.ToolRevision != f.tool && fmt.Sprint(detail["tool"]) != f.tool && !strings.HasSuffix(e.ToolRevision, "/"+f.tool) {
		return false
	}
	if f.rule != "" && !matchRule(detail, f.rule) {
		return false
	}
	if !f.since.IsZero() || !f.until.IsZero() {
		t, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil || (!f.since.IsZero() && t.Before(f.since)) || (!f.until.IsZero() && !t.Before(f.until)) {
			return false
		}
	}
	if f.text != "" {
		b, _ := json.Marshal(e)
		if !strings.Contains(strings.ToLower(string(b)), f.text) {
			return false
		}
	}
	return true
}

// matchRule reports whether a decision record names the rule as decisive,
// by rule-revision ID ("r2/dev/fs-read") or by rule ID ("fs-read").
func matchRule(detail map[string]any, rule string) bool {
	var rules []string
	switch v := detail["decisive_rules"].(type) {
	case []any:
		for _, x := range v {
			rules = append(rules, fmt.Sprint(x))
		}
	case []string:
		rules = v
	}
	for _, r := range rules {
		if r == rule || strings.HasSuffix(r, "/"+rule) {
			return true
		}
	}
	return false
}

func (c *Console) readEvents() ([]audit.Event, error) {
	if c.d.JournalDir == "" {
		return nil, fmt.Errorf("no journal directory configured")
	}
	return audit.ReadEvents(c.d.JournalDir)
}

func intParam(r *http.Request, name string, def, max int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("%s must be an integer from 1 to %d", name, max)
	}
	return n, nil
}

// listEvents is the journal browser: matching events, newest first, a page
// at a time. `before` is the event_id of the last event of the previous
// page.
func (c *Console) listEvents(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	limit, err := intParam(r, "limit", DefaultPageSize, MaxPageSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	evs, err := c.readEvents()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unreadable", err.Error())
		return
	}
	before := r.URL.Query().Get("before")
	start := len(evs) - 1
	if before != "" {
		start = -2
		for i := len(evs) - 1; i >= 0; i-- {
			if evs[i].EventID == before {
				start = i - 1
				break
			}
		}
		if start == -2 {
			writeError(w, http.StatusBadRequest, "bad_request", "before names no event of the journal")
			return
		}
	}
	page := []audit.Event{}
	next := ""
	for i := start; i >= 0; i-- {
		if !f.match(evs[i]) {
			continue
		}
		if len(page) == limit {
			next = page[len(page)-1].EventID
			break
		}
		page = append(page, evs[i])
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": page, "next_before": next, "journal_events": len(evs)})
}

// getEvent returns one event and, when it belongs to a call, every event
// with the same correlation ID in journal order (the call's phases).
func (c *Console) getEvent(w http.ResponseWriter, r *http.Request) {
	evs, err := c.readEvents()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unreadable", err.Error())
		return
	}
	id := r.PathValue("id")
	for i, e := range evs {
		if e.EventID != id {
			continue
		}
		related := []audit.Event{}
		if e.CorrelationID != "" {
			for _, o := range evs {
				if o.CorrelationID == e.CorrelationID {
					related = append(related, o)
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"event": e, "position": i + 1, "related": related})
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "no event with this ID in the journal")
}

// csvCell neutralises spreadsheet formulas (SR-6.17-1).
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@", rune(s[0])) {
		return "'" + s
	}
	return s
}

var csvHeader = []string{"event_id", "time", "class", "phase", "origin", "correlation_id", "session_id", "principal_id", "decision_id",
	"policy_revision", "server_revision", "tool_revision", "outcome", "reason_code", "policy_status", "detail"}

func csvRow(e audit.Event) []string {
	detail := ""
	if e.Detail != nil {
		b, _ := json.Marshal(e.Detail)
		detail = string(b)
	}
	row := []string{e.EventID, e.Time, e.Class, string(e.Phase), e.Origin, e.CorrelationID, e.SessionID, e.PrincipalID, e.DecisionID,
		e.PolicyRevision, e.ServerRevision, e.ToolRevision, e.Outcome, e.ReasonCode, e.PolicyStatus, detail}
	for i := range row {
		row[i] = csvCell(row[i])
	}
	return row
}

// export writes the matching events, oldest first, as CSV or JSON Lines.
// The export is recorded before any data is sent.
func (c *Console) export(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "jsonl" {
		writeError(w, http.StatusBadRequest, "bad_request", "format must be csv or jsonl")
		return
	}
	f, err := parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	evs, err := c.readEvents()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unreadable", err.Error())
		return
	}
	sel := []audit.Event{}
	for _, e := range evs {
		if f.match(e) {
			sel = append(sel, e)
		}
	}
	if len(sel) > MaxExportEvents {
		writeError(w, http.StatusRequestEntityTooLarge, "export_too_large", fmt.Sprintf("%d events match; narrow the filter to at most %d", len(sel), MaxExportEvents))
		return
	}
	if err := c.commit(r, "exported", "AUDIT_EXPORTED", audit.Event{Detail: map[string]any{"format": format, "events": len(sel), "query": r.URL.RawQuery}}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "the evidence journal could not record the export")
		return
	}
	name := "smcp-journal-" + c.d.Now().UTC().Format("20060102T150405Z") + "." + format
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	bw := bufio.NewWriter(w)
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(bw)
		_ = cw.Write(csvHeader)
		for _, e := range sel {
			_ = cw.Write(csvRow(e))
		}
		cw.Flush()
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
		enc := json.NewEncoder(bw)
		for _, e := range sel {
			_ = enc.Encode(e)
		}
	}
	if err := bw.Flush(); err != nil {
		c.d.Log.Warn("audit export interrupted", "err", err)
	}
}

// VerifyResult is the outcome of a journal verification.
type VerifyResult struct {
	Status        string   `json:"status"` // verified, failed, not_run
	Error         string   `json:"error,omitempty"`
	Segments      int      `json:"segments"`
	Events        int      `json:"events"`
	OpenSegment   string   `json:"open_segment,omitempty"`
	TruncatedTail bool     `json:"truncated_tail"`
	Recovered     []string `json:"recovered"`
	AnchorSegment int      `json:"anchor_segment"`
	Findings      []string `json:"findings"`
	CheckedAt     string   `json:"checked_at,omitempty"`
	DurationMS    int64    `json:"duration_ms"`
	CheckedBy     string   `json:"checked_by,omitempty"`
}

func (c *Console) lastVerification(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	v := c.lastVerify
	c.mu.Unlock()
	if v == nil {
		writeJSON(w, http.StatusOK, VerifyResult{Status: "not_run", Recovered: []string{}, Findings: []string{}})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// verifyNow runs the FR-7.5 verifier over the journal and records the
// result. Concurrent requests run one verification at a time.
func (c *Console) verifyNow(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {}")
		return
	}
	if c.d.JournalDir == "" || c.d.PublicKey == nil {
		writeError(w, http.StatusServiceUnavailable, "journal_unreadable", "no journal or evidence public key configured")
		return
	}
	c.verifying.Lock()
	start := c.d.Now()
	rep, err := audit.VerifyWith(c.d.JournalDir, c.d.PublicKey, audit.VerifyOptions{AnchorPath: c.d.AnchorPath})
	c.verifying.Unlock()
	res := &VerifyResult{Status: "verified", Segments: rep.Segments, Events: rep.Events, OpenSegment: rep.Open, TruncatedTail: rep.TruncatedTail,
		Recovered: append([]string{}, rep.Recovered...), AnchorSegment: rep.AnchorSegment, Findings: append([]string{}, rep.Findings()...),
		CheckedAt: rfc3339(start), DurationMS: c.d.Now().Sub(start).Milliseconds(), CheckedBy: adminapi.ActorOf(r)}
	if err != nil {
		res.Status, res.Error = "failed", err.Error()
	}
	reason := "JOURNAL_VERIFIED"
	if err != nil {
		reason = "JOURNAL_VERIFY_FAILED"
	}
	if cerr := c.commit(r, res.Status, reason, audit.Event{Detail: map[string]any{"segments": res.Segments, "events": res.Events, "error": res.Error}}); cerr != nil {
		c.d.Log.Error("evidence write failed", "err", cerr)
	}
	c.mu.Lock()
	c.lastVerify = res
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, res)
}

// StreamEvent is the summary of an evidence event sent on the stream.
type StreamEvent struct {
	EventID       string `json:"event_id"`
	Time          string `json:"time"`
	Class         string `json:"class"`
	Phase         string `json:"phase,omitempty"`
	Origin        string `json:"origin"`
	Outcome       string `json:"outcome,omitempty"`
	ReasonCode    string `json:"reason_code,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

// hub fans evidence out to open stream connections. A subscriber that does
// not keep up loses events; the stream is a change signal, the journal is
// the record.
type hub struct {
	mu   sync.Mutex
	subs map[chan StreamEvent]struct{}
}

func newHub() *hub { return &hub{subs: map[chan StreamEvent]struct{}{}} }

func (h *hub) publish(e audit.Event) {
	s := StreamEvent{EventID: e.EventID, Time: e.Time, Class: e.Class, Phase: string(e.Phase), Origin: e.Origin, Outcome: e.Outcome,
		ReasonCode: e.ReasonCode, SessionID: e.SessionID, CorrelationID: e.CorrelationID}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- s:
		default:
		}
	}
}

func (h *hub) subscribe() (chan StreamEvent, func(), bool) {
	ch := make(chan StreamEvent, streamBuffer)
	h.mu.Lock()
	if len(h.subs) >= maxStreams {
		h.mu.Unlock()
		return nil, nil, false
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}, true
}

// streamEvents is a text/event-stream with one `audit` event per evidence
// event the journal accepts (FR-8.23), and a keep-alive comment every 15 s.
func (c *Console) streamEvents(w http.ResponseWriter, r *http.Request) {
	ch, cancel, ok := c.stream.subscribe()
	if !ok {
		w.Header().Set("Retry-After", "15")
		writeError(w, http.StatusServiceUnavailable, "too_many_streams", "too many evidence streams are open")
		return
	}
	defer cancel()
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, ": stream open\n\n"); err != nil || rc.Flush() != nil {
		return
	}
	t := time.NewTicker(streamKeepAlive)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if !adminapi.StillAuthenticated(r) { // signed out or expired
				return
			}
			b, _ := json.Marshal(e)
			if _, err := io.WriteString(w, "event: audit\ndata: "+string(b)+"\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		case <-t.C:
			if !adminapi.StillAuthenticated(r) {
				return
			}
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		}
	}
}
