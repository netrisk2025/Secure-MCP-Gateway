package analytics

import (
	"fmt"
	"log/slog"
	"math"
	"runtime/metrics"
	"sync"
	"sync/atomic"
)

// Degradation stages of the observation path (FR-9.12), applied one step
// per evaluation, in this order, while the path is overloaded, and lifted
// in reverse order once it is not. Enforcement never degrades: only what
// the Observation Collector captures and keeps changes.
const (
	StageNormal          = 0
	StageReducedSampling = 1 // normal-band sampling at a tenth of its rate
	StageS3Suspended     = 2 // S3 parameters are no longer captured
	StageCampaignsPaused = 3 // research campaigns capture nothing
	StageCachesShrunk    = 4 // per-session caches shrunk to their floor
)

// StageNames name the stages in status and health output.
var StageNames = []string{"normal", "reduced_sampling", "s3_capture_suspended", "campaigns_paused", "caches_shrunk"}

// degrader decides the stage. Overload is any of: the store writer's queue
// at 80% or more (the P2 backpressure signal, FR-9.6), the heap above 90%
// of the observation memory budget, or less than 10% of host memory
// available.
type degrader struct {
	budget   int64
	heap     func() int64
	hostFree func() (float64, bool)
	pressure func() bool
	log      *slog.Logger

	stage  atomic.Int32
	mu     sync.Mutex
	reason string
}

func newDegrader(budget int64, pressure func() bool, log *slog.Logger) *degrader {
	return &degrader{budget: budget, heap: heapBytes, hostFree: hostAvailableNow, pressure: pressure, log: log}
}

var hostAvailImpl atomic.Pointer[func() (float64, bool)]

// SetHostAvailable replaces the host available-memory measurement (tests)
// and returns a function that restores the real one.
func SetHostAvailable(f func() (float64, bool)) (restore func()) {
	hostAvailImpl.Store(&f)
	return func() { hostAvailImpl.Store(nil) }
}

func hostAvailableNow() (float64, bool) {
	if f := hostAvailImpl.Load(); f != nil {
		return (*f)()
	}
	return hostAvailable()
}

// Stage returns the current stage.
func (d *degrader) Stage() int {
	if d == nil {
		return StageNormal
	}
	return int(d.stage.Load())
}

// Reason returns why the path was last found overloaded ("" when it is
// not).
func (d *degrader) Reason() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reason
}

// overloaded reports whether a degradation trigger holds, and which.
func (d *degrader) overloaded() string {
	if d.pressure != nil && d.pressure() {
		return "store writer queue at 80% or more of its capacity (backpressure)"
	}
	if d.budget > 0 && d.heap != nil {
		if h := d.heap(); h*10 > d.budget*9 {
			return fmt.Sprintf("heap %d MiB above 90%% of the %d MiB observation budget", h>>20, d.budget>>20)
		}
	}
	if d.hostFree != nil {
		if f, ok := d.hostFree(); ok && f < 0.10 {
			return fmt.Sprintf("%.0f%% of host memory available", f*100)
		}
	}
	return ""
}

// step moves one stage toward the state the triggers call for and reports
// the new stage and whether it changed.
func (d *degrader) step() (int, bool) {
	why := d.overloaded()
	d.mu.Lock()
	d.reason = why
	d.mu.Unlock()
	cur := int(d.stage.Load())
	next := cur
	switch {
	case why != "" && cur < StageCachesShrunk:
		next = cur + 1
	case why == "" && cur > StageNormal:
		next = cur - 1
	}
	if next == cur {
		return cur, false
	}
	d.stage.Store(int32(next)) //nolint:gosec // next is a stage, 0 to 4
	if d.log != nil {
		d.log.Warn("observation degradation stage changed", "from", StageNames[cur], "to", StageNames[next], "reason", why)
	}
	return next, true
}

// heapBytes is the live heap of the process.
func heapBytes() int64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	v := s[0].Value.Uint64()
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}
