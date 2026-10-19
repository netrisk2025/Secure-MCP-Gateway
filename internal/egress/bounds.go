package egress

import (
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Limit sources (FR-5.38). Each outbound operation is bounded in request
// size, response size and duration by the smallest of:
//
//   - the Runtime Profile: the [egress] limits and the grant's own
//     (release 1.x reads the Runtime Profile from the configuration,
//     FR-3.26);
//   - the manifest: the limits an egress rule of the server's verified
//     manifest declares for the destination (SetManifestLimits);
//   - the decision obligations: the egress_limits of the permit rule that
//     authorized the call the operation serves, carried by the call's
//     egress capability (pipeline.Binding.Egress). Without required
//     capabilities an operation is not bound to one call, and the
//     tightest obligation of the calls the instance is serving applies.
//
// The record of each authorized operation carries the bounds applied.

// ManifestLimit is one egress rule of a server's verified manifest with
// the limits it declares. Zero sets no bound.
type ManifestLimit struct {
	Host          string // exact name or "*.suffix"
	Ports         []int
	RequestBytes  int64
	ResponseBytes int64
	Timeout       time.Duration
}

// ManifestLimits returns the manifest egress rules of a server alias; nil
// for a server without a verified manifest.
type ManifestLimits func(server string) []ManifestLimit

// SetManifestLimits installs the manifest source. app.Start calls it once
// the packaged servers are resolved.
func (b *Broker) SetManifestLimits(f ManifestLimits) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.manifest = f
	b.mu.Unlock()
}

// track records the egress-limit obligation of one call to in while
// capabilities are not required; the returned function ends the call.
func (b *Broker) track(in *instance, ob pipeline.EgressLimits) func() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if in.calls == nil {
		in.calls = map[uint64]pipeline.EgressLimits{}
	}
	in.seq++
	id := in.seq
	in.calls[id] = ob
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			delete(in.calls, id)
			b.mu.Unlock()
		})
	}
}

// inProgress returns the tightest egress-limit obligation, per bound, of
// the calls the instance is serving (zero when none sets one).
func (b *Broker) inProgress(instanceID string) pipeline.EgressLimits {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out pipeline.EgressLimits
	in := b.instances[instanceID]
	if in == nil {
		return out
	}
	low := func(cur, v int64) int64 {
		if v > 0 && (cur == 0 || v < cur) {
			return v
		}
		return cur
	}
	for _, ob := range in.calls {
		out.RequestBytes = low(out.RequestBytes, ob.RequestBytes)
		out.ResponseBytes = low(out.ResponseBytes, ob.ResponseBytes)
		out.Timeout = time.Duration(low(int64(out.Timeout), int64(ob.Timeout)))
	}
	return out
}

// Bounds are the limits applied to one operation, in its record.
type Bounds struct {
	RequestBytes  int64 `json:"request_bytes"`
	ResponseBytes int64 `json:"response_bytes"`
	TimeoutMS     int64 `json:"timeout_ms"`
}

// tighten lowers each bound of l to the corresponding positive bound.
func (l Limits) tighten(req, resp int64, timeout time.Duration) Limits {
	if req > 0 && req < l.RequestBytes {
		l.RequestBytes = req
	}
	if resp > 0 && resp < l.ResponseBytes {
		l.ResponseBytes = resp
	}
	if timeout > 0 && timeout < l.OperationTimeout {
		l.OperationTimeout = timeout
	}
	return l
}

// manifestCovers reports whether a manifest rule host covers host.
func manifestCovers(rule, host string) bool {
	rule = strings.ToLower(strings.TrimSuffix(rule, "."))
	if rule == host {
		return true
	}
	suffix, ok := strings.CutPrefix(rule, "*.")
	return ok && strings.HasSuffix(host, "."+suffix) && len(host) > len(suffix)+1
}

// opLimits returns the limits of one authorized operation of rec to
// host:port under grant g: the smallest of the configuration and grant,
// every manifest rule of the server covering the destination, and the
// obligation of the call whose capability the operation spent. The
// result is recorded in rec.
func (b *Broker) opLimits(rec *Record, g Grant, host string, port int) Limits {
	lim := b.limits.effective(g)
	b.mu.Lock()
	src := b.manifest
	b.mu.Unlock()
	if src != nil {
		for _, r := range src(rec.Server) {
			if manifestCovers(r.Host, host) && slices.Contains(r.Ports, port) {
				lim = lim.tighten(r.RequestBytes, r.ResponseBytes, r.Timeout)
			}
		}
	}
	ob := rec.obligation
	lim = lim.tighten(ob.RequestBytes, ob.ResponseBytes, ob.Timeout)
	rec.Bounds = &Bounds{RequestBytes: lim.RequestBytes, ResponseBytes: lim.ResponseBytes, TimeoutMS: lim.OperationTimeout.Milliseconds()}
	return lim
}
