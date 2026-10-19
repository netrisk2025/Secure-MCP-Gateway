package sandbox

import (
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Instance states.
const (
	StateStarting = "starting"
	StateRunning  = "running"
	StateExited   = "exited"
	StateKilled   = "killed"
)

// Sample is one reading of an instance's cgroup (FR-5.33 resource
// observables).
type Sample struct {
	At            time.Time `json:"at"`
	MemoryCurrent int64     `json:"memory_current_bytes"`
	MemoryPeak    int64     `json:"memory_peak_bytes"`
	CPUUsageUsec  int64     `json:"cpu_usage_usec"`
	Pids          int       `json:"pids"`
	PidsPeak      int       `json:"pids_peak"`
	OOMEvents     uint64    `json:"oom_events"`
	OOMKills      uint64    `json:"oom_kills"`
	PidsMaxEvents uint64    `json:"pids_max_events"`
	Procs         []int     `json:"-"`
}

// Observation is one runtime event of an instance as kept in the
// instance table (the evidence journal holds the complete record).
type Observation struct {
	At     time.Time      `json:"at"`
	Kind   string         `json:"kind"`
	Reason string         `json:"reason_code,omitempty"`
	Action string         `json:"action,omitempty"`
	Detail map[string]any `json:"detail,omitempty"`
}

const maxObservations = 64

// Instance is one row of the E-15 instance table.
type Instance struct {
	ID      string
	Alias   string
	Name    string
	Spec    LaunchSpec
	Started time.Time

	proc   *container
	stderr *pipeline.Ring

	mu         sync.Mutex
	State      string
	closing    bool
	cgroup     string
	mainPID    int
	seen       map[int]bool
	last       Sample
	base       Sample
	baseSet    bool
	obs        []Observation
	deviations int
	exitCode   *int
	oomKilled  bool
	killReason string
	ended      time.Time
	removed    bool
	exitOnce   sync.Once
}

// setClosing records that the owner asked the instance to stop; expected
// is false when the instance had already ended by itself.
func (in *Instance) setClosing(expected bool) {
	in.mu.Lock()
	if expected {
		in.closing = true
	}
	in.mu.Unlock()
}

func (in *Instance) running() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.State == StateStarting || in.State == StateRunning
}

func (in *Instance) observe(o Observation) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.obs = append(in.obs, o)
	if len(in.obs) > maxObservations {
		in.obs = append([]Observation(nil), in.obs[len(in.obs)-maxObservations:]...)
	}
}

// InstanceView is the control API form of an instance.
type InstanceView struct {
	ID           string        `json:"instance_id"`
	Alias        string        `json:"alias"`
	Container    string        `json:"container"`
	State        string        `json:"state"`
	Removed      bool          `json:"removed"`
	Scope        string        `json:"scope"`
	Started      time.Time     `json:"started"`
	Ended        *time.Time    `json:"ended,omitempty"`
	ExitCode     *int          `json:"exit_code,omitempty"`
	OOMKilled    bool          `json:"oom_killed"`
	KillReason   string        `json:"kill_reason,omitempty"`
	Deviations   int           `json:"deviations"`
	Usage        Sample        `json:"usage"`
	LaunchSpec   LaunchSpec    `json:"launch_spec"`
	Observations []Observation `json:"observations"`
}

// View returns a consistent snapshot.
func (in *Instance) View() InstanceView {
	in.mu.Lock()
	defer in.mu.Unlock()
	v := InstanceView{ID: in.ID, Alias: in.Alias, Container: in.Name, State: in.State, Removed: in.removed, Scope: in.Spec.Scope, Started: in.Started,
		ExitCode: in.exitCode, OOMKilled: in.oomKilled, KillReason: in.killReason, Deviations: in.deviations, Usage: in.last,
		LaunchSpec: in.Spec, Observations: append([]Observation{}, in.obs...)}
	if !in.ended.IsZero() {
		e := in.ended
		v.Ended = &e
	}
	return v
}
