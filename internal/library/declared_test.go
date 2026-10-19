package library

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// specRecorder wraps a launcher and keeps the specs it is given.
type specRecorder struct {
	pipeline.Launcher
	mu    sync.Mutex
	specs []pipeline.ServerSpec
}

func (s *specRecorder) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	s.mu.Lock()
	s.specs = append(s.specs, spec)
	s.mu.Unlock()
	return s.Launcher.Launch(ctx, spec)
}

// TestManifestBehaviorReachesTheLaunch: the process-creation behavior a
// verified manifest declares (capabilities.spawns_processes) is passed to
// the launcher with the launch, where the Runtime Monitor evaluates
// process creation against it (FR-5.34; the monitor side is
// internal/sandbox TestDeclaredBehaviorRules).
func TestManifestBehaviorReachesTheLaunch(t *testing.T) {
	reqtest.Partial(t, "FR-5.34")
	for _, spawns := range []bool{false, true} {
		e := newEnv(t)
		dir := e.pkg(pkgtest.Spec{ID: "fx-id", Revision: "1", Tools: []*mcp.Tool{pkgtest.EchoTool(fixtureDesc)},
			Edit: func(m *packaging.Manifest, _ *packaging.Provenance) { m.Capabilities.SpawnsProcesses = spawns }})
		rc, err := e.lib.Import(dir, ImportOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.lib.Enable("fx-id", "1", EnableOptions{}); err != nil {
			t.Fatal(err)
		}
		r := &rtEnv{env: e, rt: NewRuntime(e.lib, RuntimeOptions{ScanInterval: time.Hour}), fx: &fixtureServer{desc: fixtureDesc}, sha: rc.ArtifactSHA256}
		rec := &specRecorder{Launcher: r.launcher()}
		out, l, err := r.rt.Prepare(r.rec, []config.Server{{Alias: "fx", Package: "fx-id"}}, rec, true)
		if err != nil {
			t.Fatal(err)
		}
		p, err := l.Launch(context.Background(), pipeline.ServerSpec{Alias: out[0].Alias, Command: out[0].Command, Args: out[0].Args, Env: out[0].Env})
		if err != nil {
			t.Fatal(err)
		}
		p.Close()
		r.rt.Close()
		rec.mu.Lock()
		got := rec.specs
		rec.mu.Unlock()
		if len(got) != 1 || got[0].SpawnsProcesses == nil || *got[0].SpawnsProcesses != spawns {
			t.Fatalf("spawns_processes %v: launch specs %+v", spawns, got)
		}
	}
}
