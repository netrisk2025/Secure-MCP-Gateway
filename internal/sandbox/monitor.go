package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Containment actions (FR-5.35). The registry suspends a revision whose
// instance keeps ending (FR-5.12); suspend-revision and suspend-session are
// not containment actions in release 1.0.
const (
	ActionAlert = "alert"
	ActionKill  = "kill-instance"
)

// Reason codes of runtime evidence.
const (
	ReasonMemoryLimit        = "MEMORY_LIMIT"
	ReasonPidsLimit          = "PIDS_LIMIT"
	ReasonUndeclaredProcess  = "UNDECLARED_PROCESS"
	ReasonExecIntoInstance   = "EXEC_INTO_INSTANCE"
	ReasonOperatorKill       = "OPERATOR_KILL"
	ReasonUnexpectedExit     = "INSTANCE_EXITED_UNEXPECTEDLY"
	ReasonMonitorUnavailable = "MONITOR_UNAVAILABLE"
)

// Monitor is the Runtime Monitor (E-17). Each instance has a polling
// goroutine that samples its cgroup; one goroutine reads the Podman event
// stream for the Gateway's containers.
type Monitor struct {
	l      *Launcher
	stopCh chan struct{}
	once   sync.Once
}

func newMonitor(l *Launcher) *Monitor { return &Monitor{l: l, stopCh: make(chan struct{})} }

func (m *Monitor) stop() { m.once.Do(func() { close(m.stopCh) }) }

// inspect reads fields of a container through `podman inspect`.
func (m *Monitor) inspect(name string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := m.l.podman(ctx, "inspect", "--type", "container", "--format",
		"{{.State.Status}}|{{.State.Pid}}|{{.State.CgroupPath}}|{{.State.ExitCode}}|{{.State.OOMKilled}}", name).Output()
	if err != nil {
		return nil, err
	}
	f := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(f) < 5 {
		return nil, errInspect
	}
	return map[string]string{"status": f[0], "pid": f[1], "cgroup": f[2], "exit_code": f[3], "oom_killed": f[4]}, nil
}

type inspectError string

func (e inspectError) Error() string { return string(e) }

const errInspect = inspectError("unexpected podman inspect output")

// watch samples one instance until it exits.
func (m *Monitor) watch(in *Instance) {
	interval := m.l.o.Runtime.MonitorInterval.Duration
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	kick := make(chan struct{}, 1)
	var stopWatch func()
	defer func() {
		if stopWatch != nil {
			stopWatch()
		}
	}()
	failures := 0
	for {
		if !in.running() {
			return
		}
		m.sampleOnce(in, &failures)
		if stopWatch == nil {
			in.mu.Lock()
			cg := in.cgroup
			in.mu.Unlock()
			if cg != "" {
				stop, err := watchCgroupEvents(cg, func() {
					select {
					case kick <- struct{}{}:
					default:
					}
				})
				if err != nil {
					stop = func() {} // polling only
				}
				stopWatch = stop
			}
		}
		select {
		case <-m.stopCh:
			return
		case <-in.proc.done:
			return
		case <-t.C:
		case <-kick:
		}
	}
}

// locate waits until the container runs and records its cgroup and main
// PID, or until the instance exits or the bound passes.
func (m *Monitor) locate(in *Instance, done <-chan struct{}, bound time.Duration) {
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if m.locateOnce(in) {
			return
		}
		select {
		case <-done:
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (m *Monitor) locateOnce(in *Instance) bool {
	info, err := m.inspect(in.Name)
	if err != nil || info["status"] != "running" || info["cgroup"] == "" {
		return false
	}
	pid, _ := strconv.Atoi(info["pid"])
	cg := filepath.Join(m.l.o.CgroupRoot, filepath.Clean("/"+info["cgroup"]))
	in.mu.Lock()
	in.cgroup, in.mainPID = cg, pid
	if in.State == StateStarting {
		in.State = StateRunning
	}
	in.mu.Unlock()
	return true
}

func (m *Monitor) sampleOnce(in *Instance, failures *int) {
	in.mu.Lock()
	cg := in.cgroup
	in.mu.Unlock()
	if cg == "" {
		if !m.locateOnce(in) {
			*failures++
			if *failures == 20 {
				m.l.log.Warn("runtime monitor cannot locate the instance cgroup", "alias", in.Alias, "container", in.Name)
				m.l.record(audit.Event{Class: EvidenceClass, Origin: OriginMonitor, Outcome: "monitor_degraded", ReasonCode: ReasonMonitorUnavailable,
					PolicyStatus: "not_evaluated", Detail: map[string]any{"alias": in.Alias, "instance_id": in.ID}}, false)
			}
			return
		}
		in.mu.Lock()
		cg = in.cgroup
		in.mu.Unlock()
	}
	s, err := ReadCgroup(cg, m.l.o.Now().UTC())
	if err != nil {
		return // the cgroup is removed when the container exits
	}
	m.evaluate(in, s)
}

// keepMonotonic carries the cgroup's peaks and event counters over from the
// previous sample when the new one is lower. They never decrease while the
// cgroup exists, but a cgroup that is being removed (a kernel OOM kill ends
// the container) can still be found while its files are gone, and ReadCgroup
// then reads zeros. Without this, that last sample erased the OOM kill and
// the memory peak the exit evidence is judged by.
func keepMonotonic(prev, s Sample) Sample {
	s.MemoryPeak = max(s.MemoryPeak, prev.MemoryPeak)
	s.PidsPeak = max(s.PidsPeak, prev.PidsPeak)
	s.OOMEvents = max(s.OOMEvents, prev.OOMEvents)
	s.OOMKills = max(s.OOMKills, prev.OOMKills)
	s.PidsMaxEvents = max(s.PidsMaxEvents, prev.PidsMaxEvents)
	s.CPUUsageUsec = max(s.CPUUsageUsec, prev.CPUUsageUsec)
	return s
}

// evaluate applies the limit and declared-behavior rules to a sample.
func (m *Monitor) evaluate(in *Instance, s Sample) {
	in.mu.Lock()
	if !in.baseSet {
		// Every instance runs in a container cgroup of its own, created
		// with the container, so its event counters start at zero and the
		// baseline stays zero: a breach between the start and the first
		// sample (a fork bomb at startup) is a breach, not the baseline.
		in.baseSet = true
		if in.seen == nil {
			in.seen = map[int]bool{}
		}
	}
	prev := in.last
	s = keepMonotonic(prev, s)
	in.last = s
	base := in.base
	main := in.mainPID
	allow := in.Spec.Profile.AllowSpawn
	rule := in.Spec.Profile.OnDeviation
	var fresh []int
	for _, p := range s.Procs {
		if !in.seen[p] {
			in.seen[p] = true
			fresh = append(fresh, p)
		}
	}
	in.mu.Unlock()

	if s.OOMKills > base.OOMKills && s.OOMKills > prev.OOMKills {
		m.contain(in, ActionKill, ReasonMemoryLimit, map[string]any{"oom_kills": s.OOMKills, "memory_peak_bytes": s.MemoryPeak,
			"memory_limit_bytes": in.Spec.Limits.MemoryBytes})
		return
	}
	if s.PidsMaxEvents > base.PidsMaxEvents && s.PidsMaxEvents > prev.PidsMaxEvents {
		m.contain(in, ActionKill, ReasonPidsLimit, map[string]any{"pids_max_events": s.PidsMaxEvents, "pids_limit": in.Spec.Limits.Pids})
		return
	}
	for _, p := range fresh {
		comm := procComm(p)
		detail := map[string]any{"alias": in.Alias, "instance_id": in.ID, "pid": p, "comm": comm}
		in.observe(Observation{At: s.At, Kind: "process_created", Detail: map[string]any{"pid": p, "comm": comm}})
		m.l.record(audit.Event{Class: EvidenceClass, Origin: OriginMonitor, Outcome: "process_created", PolicyStatus: "not_evaluated", Detail: detail}, false)
		if p != main && main != 0 && !allow {
			m.contain(in, rule, ReasonUndeclaredProcess, map[string]any{"pid": p, "comm": comm})
		}
	}
}

// contain records a deviation or breach and performs its action.
func (m *Monitor) contain(in *Instance, action, reason string, detail map[string]any) {
	start := time.Now()
	if action != ActionKill {
		action = ActionAlert
	}
	d := map[string]any{"alias": in.Alias, "instance_id": in.ID, "container": in.Name, "action": action}
	for k, v := range detail {
		d[k] = v
	}
	in.mu.Lock()
	if reason != ReasonOperatorKill {
		in.deviations++
	}
	already := in.State == StateKilled
	if action == ActionKill && !already {
		in.State = StateKilled
		in.killReason = reason
	}
	in.mu.Unlock()
	in.observe(Observation{At: m.l.o.Now().UTC(), Kind: "deviation", Reason: reason, Action: action, Detail: detail})
	outcome := "deviation"
	switch reason {
	case ReasonOperatorKill:
		outcome = "instance_killed"
	case ReasonMemoryLimit, ReasonPidsLimit:
		outcome = "limit_breach"
	}
	if action == ActionKill && !already {
		in.proc.kill()
		d["latency_ms"] = time.Since(start).Milliseconds()
	}
	m.l.record(audit.Event{Class: EvidenceClass, Origin: OriginMonitor, Outcome: outcome, ReasonCode: reason, PolicyStatus: "not_evaluated", Detail: d}, true)
	m.l.log.Warn("runtime containment", "alias", in.Alias, "container", in.Name, "reason", reason, "action", action)
}

// exited records the end of an instance once.
func (m *Monitor) exited(in *Instance) {
	in.exitOnce.Do(func() {
		info, _ := m.inspect(in.Name)
		in.mu.Lock()
		if in.State != StateKilled {
			in.State = StateExited
		}
		in.ended = m.l.o.Now().UTC()
		if info != nil {
			if c, err := strconv.Atoi(info["exit_code"]); err == nil {
				in.exitCode = &c
			}
			in.oomKilled = info["oom_killed"] == "true"
		}
		closing, killed, last, base := in.closing, in.killReason, in.last, in.base
		code := in.exitCode
		oom := in.oomKilled
		in.mu.Unlock()
		reason := ""
		if !closing && killed == "" {
			reason = ReasonUnexpectedExit
		}
		// Rootless Podman does not always report OOMKilled; an unrequested
		// SIGKILL (exit 137) after the cgroup hit its memory limit is the
		// kernel's OOM kill.
		limitHit := last.OOMKills > base.OOMKills || last.OOMEvents > base.OOMEvents ||
			(in.Spec.Limits.MemoryBytes > 0 && last.MemoryPeak >= in.Spec.Limits.MemoryBytes*9/10)
		if killed == "" && !closing && (oom || (code != nil && *code == 137 && limitHit)) {
			reason = ReasonMemoryLimit
		}
		d := map[string]any{"alias": in.Alias, "instance_id": in.ID, "container": in.Name, "expected": closing,
			"memory_peak_bytes": last.MemoryPeak, "cpu_usage_usec": last.CPUUsageUsec, "pids_peak": last.PidsPeak, "oom_killed": oom}
		if code != nil {
			d["exit_code"] = *code
		}
		if killed != "" {
			d["kill_reason"] = killed
		}
		if tail := in.stderr.Tail(); tail != "" && !closing {
			d["stderr_bytes"] = len(tail) // the content is diagnostic and stays out of evidence
		}
		in.observe(Observation{At: in.ended, Kind: "exited", Reason: reason, Detail: d})
		m.l.record(audit.Event{Class: EvidenceClass, Origin: OriginRuntime, Outcome: "instance_exited", ReasonCode: reason, PolicyStatus: "not_evaluated", Detail: d}, true)
		if !closing {
			m.l.log.Warn("server instance exited", "alias", in.Alias, "container", in.Name, "reason", reason)
		}
	})
}

// PodmanEvent is one line of `podman events --format json`.
type PodmanEvent struct {
	ID         string            `json:"ID"`
	Name       string            `json:"Name"`
	Status     string            `json:"Status"`
	Type       string            `json:"Type"`
	ExitCode   *int              `json:"ContainerExitCode,omitempty"`
	Attributes map[string]string `json:"Attributes"`
}

// runEvents follows the Podman event stream for this Gateway's containers
// until ctx ends, restarting the stream if it ends early.
func (m *Monitor) runEvents(ctx context.Context) {
	for {
		cmd := m.l.podman(ctx, "events", "--format", "json", "--filter", "type=container",
			"--filter", "label="+LabelGateway+"="+m.l.gateway)
		out, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err == nil {
			sc := bufio.NewScanner(out)
			sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
			for sc.Scan() {
				var ev PodmanEvent
				if json.Unmarshal(sc.Bytes(), &ev) == nil {
					m.HandleEvent(ev)
				}
			}
			_ = cmd.Wait()
		} else {
			m.l.log.Warn("podman events unavailable", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// HandleEvent applies one Podman event.
func (m *Monitor) HandleEvent(ev PodmanEvent) {
	if ev.Attributes[LabelGateway] != m.l.gateway {
		return
	}
	in, ok := m.l.Instance(ev.Attributes[LabelInstance])
	if !ok {
		return
	}
	switch ev.Status {
	case "exec":
		in.observe(Observation{At: m.l.o.Now().UTC(), Kind: "exec"})
		m.contain(in, in.Spec.Profile.OnDeviation, ReasonExecIntoInstance, nil)
	case "oom":
		m.contain(in, ActionKill, ReasonMemoryLimit, map[string]any{"source": "podman-event"})
	case "start":
		in.mu.Lock()
		if in.State == StateStarting {
			in.State = StateRunning
		}
		in.mu.Unlock()
	}
}
