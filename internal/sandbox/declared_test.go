package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestDeclaredBehaviorRules is FR-5.34: each runtime event is evaluated
// against the server's declared behavior. An instance whose manifest
// declares no process creation (spawns_processes false) and spawns a
// process gets a deviation event; the same event for an instance whose
// manifest declares process creation is recorded as a process creation
// and is no deviation. (internal/library passes the manifest's
// declaration with the launch: TestManifestBehaviorReachesTheLaunch.)
func TestDeclaredBehaviorRules(t *testing.T) {
	reqtest.Verifies(t, "FR-5.34")
	for _, declared := range []bool{false, true} {
		rt := testRuntime()
		rt.Servers = []config.RuntimeServer{{Alias: "db", OnDeviation: ActionAlert}}
		h := newHarness(t, rt)
		spec := h.spec("db")
		spec.SpawnsProcesses = &declared
		p, err := h.l.Launch(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		connect(t, p)
		name := h.l.Instances()[0].Container
		eventually(t, 3*time.Second, "first sample", func() bool { return findEvent(h.mem.Events(), "process_created", "") != nil })
		if got := h.l.Instances()[0].LaunchSpec.Profile.AllowSpawn; got != declared {
			t.Fatalf("declared %v: launch profile allow_spawn %v", declared, got)
		}
		pid, _ := os.ReadFile(filepath.Join(h.dir, name+".pid"))
		h.cg(name, "cgroup.procs", strings.TrimSpace(string(pid))+"\n777777\n")
		eventually(t, 3*time.Second, "process creation", func() bool {
			for _, e := range h.mem.Events() {
				if d, ok := e.Detail.(map[string]any); ok && e.Outcome == "process_created" && d["pid"] == 777777 {
					return true
				}
			}
			return false
		})
		if declared {
			time.Sleep(300 * time.Millisecond) // further samples: still no deviation
			if e := findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess); e != nil {
				t.Fatalf("declared process creation reported as a deviation: %+v", e)
			}
		} else {
			eventually(t, 3*time.Second, "deviation", func() bool { return findEvent(h.mem.Events(), "deviation", ReasonUndeclaredProcess) != nil })
		}
		p.Close()
	}
}
