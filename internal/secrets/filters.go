package secrets

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Filter IDs registered by this package. The SRS filter names
// `secret-fingerprint` (E-09, E-11) belong to the rule-set filters of the
// inspection pipelines; these filters match the vault's own delivered
// values.
const (
	FilterArgsLeak     = "secret-vault-args"
	FilterResultLeak   = "secret-vault-leak"
	FilterS2Delivery   = "secret-delivery-s2"
	FilterS2Release    = "secret-release-s2"
	orderArgsLeak      = 115 // before the built-in secret-fingerprint (120), which also knows delivered values
	orderS2Delivery    = 1000
	orderS2Release     = 0
	orderResultLeak    = 35 // before the built-in secret-fingerprint (40), so a leak still suspends the secret
	maxScannedStrings  = 1 << 16
	s2ReleaseSafetyNet = 10 * time.Minute
)

// RegisterFilters adds the broker's mandatory filters to the chains: the
// argument and result leak filters and the S2 delivery and release stages.
func (b *Broker) RegisterFilters(f *pipeline.Filters) error {
	if err := f.RegisterRequest(argsLeakFilter{b}, pipeline.Registration{Order: orderArgsLeak, Mandatory: true}); err != nil {
		return err
	}
	if err := f.RegisterRequest(s2Filter{b}, pipeline.Registration{Order: orderS2Delivery, Mandatory: true}); err != nil {
		return err
	}
	if err := f.RegisterResponse(s2Release{b}, pipeline.Registration{Order: orderS2Release, Mandatory: true}); err != nil {
		return err
	}
	return f.RegisterResponse(resultLeakFilter{b}, pipeline.Registration{Order: orderResultLeak, Mandatory: true})
}

// scanJSON scans raw JSON and every string in it after unescaping, so a
// value that JSON escapes (quotes, backslashes, <, >, &) is still found.
func scanJSON(fp *Fingerprints, raw []byte) []pipeline.SecretMatch {
	if fp.Len() == 0 || len(raw) == 0 {
		return nil
	}
	ms := fp.Scan(raw)
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ms
	}
	n := 0
	var walk func(any)
	walk = func(x any) {
		if n > maxScannedStrings {
			return
		}
		switch t := x.(type) {
		case string:
			n++
			ms = append(ms, fp.Scan([]byte(t))...)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for k, e := range t {
				n++
				ms = append(ms, fp.Scan([]byte(k))...)
				walk(e)
			}
		}
	}
	walk(v)
	return ms
}

func refsOf(ms []pipeline.SecretMatch) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		if !seen[m.SecretRef] {
			seen[m.SecretRef] = true
			out = append(out, m.SecretRef)
		}
	}
	sort.Strings(out)
	return out
}

// argsLeakFilter blocks a call whose arguments contain a delivered secret
// (SR-5.x secret-fingerprint on arguments): the harness must not be able
// to send a vault value anywhere, nor learn that a guess was right from a
// result.
type argsLeakFilter struct{ b *Broker }

func (argsLeakFilter) ID() string { return FilterArgsLeak }

func (f argsLeakFilter) FilterRequest(_ context.Context, call *pipeline.Call, args json.RawMessage) (pipeline.RequestVerdict, error) {
	ms := scanJSON(f.b.fp, args)
	if len(ms) == 0 {
		return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
	}
	refs := refsOf(ms)
	for _, ref := range refs {
		f.b.record(event{outcome: "detected", reason: ReasonInArguments, server: call.Server, ref: ref, tool: call.Tool, corr: call.CorrelationID,
			decision: call.DecisionID, serverRev: call.ServerRevision, extra: map[string]any{"surface": "arguments", "matches": len(ms)}})
	}
	return pipeline.RequestVerdict{Action: pipeline.Block, ReasonCode: ReasonInArguments,
		Finding: "arguments contain a registered secret value (" + strings.Join(refs, ", ") + ")"}, nil
}

// resultLeakFilter withholds a result that contains a delivered secret
// (FR-6.10, SR-2-1) and suspends further S2 delivery of that secret
// pending operator review (ARCH §8.5).
type resultLeakFilter struct{ b *Broker }

func (resultLeakFilter) ID() string { return FilterResultLeak }

func (f resultLeakFilter) FilterResponse(_ context.Context, call *pipeline.Call, res *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	if f.b.fp.Len() == 0 || res == nil {
		return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return pipeline.ResponseVerdict{}, err
	}
	ms := scanJSON(f.b.fp, raw)
	if len(ms) == 0 {
		return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
	}
	refs := refsOf(ms)
	for _, ref := range refs {
		f.b.Suspend(ref, "leak detected in a result of "+call.PublicName)
		_ = f.b.commit(event{outcome: "suspended", reason: ReasonLeak, server: call.Server, ref: ref, secret: f.b.vault.nameOfRef(ref), tool: call.Tool,
			corr: call.CorrelationID, decision: call.DecisionID, serverRev: call.ServerRevision, extra: map[string]any{"surface": "result", "matches": len(ms)}})
	}
	return pipeline.ResponseVerdict{Action: pipeline.Block, ReasonCode: ReasonLeak,
		Finding: "result contains a registered secret value (" + strings.Join(refs, ", ") + ")"}, nil
}

// s2Filter is the per-call delivery stage (FR-6.7). It runs last in the
// request chain, after inspection, and writes each S2 secret the call's
// tool is bound to into the instance-private file whose path the server
// received at launch. The file is deleted when the call completes: by the
// release filter when a result arrives, and in every case when the call's
// context ends (the edge cancels it when the handler returns).
type s2Filter struct{ b *Broker }

func (s2Filter) ID() string { return FilterS2Delivery }

func (f s2Filter) FilterRequest(ctx context.Context, call *pipeline.Call, _ json.RawMessage) (pipeline.RequestVerdict, error) {
	b := f.b
	b.mu.Lock()
	use, stopped, inst := b.use, b.stopped, b.instances[call.Server]
	var binds []*binding
	for _, bd := range use.byServer[call.Server] {
		if bd.Mode == ModeS2 && bd.permitsTool(call.Tool) {
			binds = append(binds, bd)
		}
	}
	b.mu.Unlock()
	if len(binds) == 0 {
		return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
	}
	var releases []func()
	fail := func(bd *binding, reason, ref string, version int) (pipeline.RequestVerdict, error) {
		for _, r := range releases {
			r()
		}
		e := event{outcome: "denied", reason: reason, b: bd, ref: ref, version: version, tool: call.Tool, corr: call.CorrelationID,
			decision: call.DecisionID, serverRev: call.ServerRevision, policyRev: use.Revision}
		if err := b.commit(e); err != nil {
			return pipeline.RequestVerdict{}, err
		}
		return pipeline.RequestVerdict{Action: pipeline.Block, ReasonCode: reason, Finding: "secret slot " + bd.Slot + " not delivered: " + reason}, nil
	}
	for _, bd := range binds {
		switch {
		case stopped:
			return fail(bd, ReasonStopped, "", 0)
		case !bd.inWindow(b.now()):
			return fail(bd, ReasonOutsideWindow, "", 0)
		case bd.SessionPurpose != "" && call.Purpose != bd.SessionPurpose:
			return fail(bd, ReasonPurpose, "", 0)
		case bd.Approval && !call.Obligations.Approval:
			return fail(bd, ReasonApproval, "", 0)
		case inst == nil || inst.s2[bd.Slot] == "":
			return fail(bd, ReasonNoInstance, "", 0)
		}
		if !b.takeRate(bd) {
			return fail(bd, ReasonRateLimited, "", 0)
		}
		op, err := b.vault.open(bd.Secret, bd.Version)
		if err != nil {
			return fail(bd, reasonFor(err), op.Ref, op.Version)
		}
		if _, susp := b.Suspended()[op.Ref]; susp {
			wipe(op.Value)
			return fail(bd, ReasonSuspended, op.Ref, op.Version)
		}
		b.fp.Register(op.Ref, op.Version, op.Value)
		rel, err := b.acquireCallFile(inst.s2[bd.Slot], op)
		wipe(op.Value)
		if err != nil {
			return fail(bd, ReasonDeliveryFailed, op.Ref, op.Version)
		}
		releases = append(releases, rel)
		if err := b.commit(event{outcome: "delivered", b: bd, ref: op.Ref, version: op.Version, tool: call.Tool, corr: call.CorrelationID,
			decision: call.DecisionID, serverRev: call.ServerRevision, policyRev: use.Revision}); err != nil {
			for _, r := range releases {
				r()
			}
			return pipeline.RequestVerdict{}, err
		}
	}
	var once sync.Once
	releaseAll := func() {
		once.Do(func() {
			for _, r := range releases {
				r()
			}
		})
	}
	b.mu.Lock()
	b.release[call.CorrelationID] = append(b.release[call.CorrelationID], releaseAll)
	b.mu.Unlock()
	corr := call.CorrelationID
	// The filter's own ctx ends with the chain deadline; the file must stay
	// until the call ends.
	callCtx := pipeline.CallContext(ctx)
	go func() {
		t := time.NewTimer(s2ReleaseSafetyNet)
		defer t.Stop()
		select {
		case <-callCtx.Done():
		case <-t.C:
		}
		b.releaseCall(corr)
	}()
	return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
}

func (b *Broker) releaseCall(corr string) {
	b.mu.Lock()
	rs := b.release[corr]
	delete(b.release, corr)
	b.mu.Unlock()
	for _, r := range rs {
		r()
	}
}

// takeRate applies the binding's calls_per_minute.
func (b *Broker) takeRate(bd *binding) bool {
	if bd.CallsPerMinute <= 0 {
		return true
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	kept := b.rates[bd.ID][:0]
	for _, t := range b.rates[bd.ID] {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	if len(kept) >= bd.CallsPerMinute {
		b.rates[bd.ID] = kept
		return false
	}
	b.rates[bd.ID] = append(kept, now)
	return true
}

// acquireCallFile writes (or shares, for concurrent calls) the per-call
// file and returns its release. The last release deletes the file.
func (b *Broker) acquireCallFile(path string, op opened) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cf := b.calls[path]
	if cf == nil || cf.version != op.Version || cf.ref != op.Ref {
		if err := writeSecretFile(path, op.Value); err != nil {
			return nil, err
		}
		if cf == nil {
			cf = &callFile{path: path}
			b.calls[path] = cf
		}
		cf.ref, cf.version = op.Ref, op.Version
	}
	cf.count++
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.calls[path] != cf {
				return
			}
			cf.count--
			if cf.count <= 0 {
				delete(b.calls, path)
				_ = scrubFile(path)
			}
		})
	}, nil
}

// s2Release deletes the call's S2 files as soon as the result is back,
// before response inspection and release.
type s2Release struct{ b *Broker }

func (s2Release) ID() string { return FilterS2Release }

func (f s2Release) FilterResponse(_ context.Context, call *pipeline.Call, _ *mcp.CallToolResult) (pipeline.ResponseVerdict, error) {
	f.b.releaseCall(call.CorrelationID)
	return pipeline.ResponseVerdict{Action: pipeline.Pass}, nil
}
