package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestRuntimeDefaults(t *testing.T) {
	reqtest.Partial(t, "SR-4.7-2")
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Runtime
	if r.Sandbox != "none" || r.MemoryBytes != 512<<20 || r.CPUs != 1 || r.Pids != 128 || r.TmpfsBytes != 64<<20 ||
		r.NoFile != 1024 || r.UserNSSize != 2048 || r.User != "1000:1000" || r.MonitorInterval.Duration != 500*time.Millisecond {
		t.Fatalf("defaults %+v", r)
	}
	cfg, err = Parse([]byte(withBefore("[profile]\nmode = \"enforced\"\n")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Runtime.Sandbox != "podman" {
		t.Fatalf("enforced mode sandbox %q", cfg.Runtime.Sandbox)
	}
	cfg, err = Parse([]byte(withBefore(`[runtime]
sandbox = "podman"
[[runtime.server]]
alias = "fs"
pids = 64
[[runtime.server.mount]]
source = "/srv/data"
`)))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Runtime.FindServer("fs")
	if s.Pids != 64 || s.Network != "none" || s.Scope != "shared" || s.UserNS != "auto" || s.OnDeviation != "alert" || len(s.Mounts) != 1 || s.Mounts[0].Write {
		t.Fatalf("server %+v", s)
	}
	if z := cfg.Runtime.FindServer("other"); z.Alias != "other" || len(z.Mounts) != 0 {
		t.Fatalf("unknown alias %+v", z)
	}
}

func TestRuntimeValidation(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("ab", 32)
	for name, extra := range map[string]string{
		"standalone with podman":  "[profile]\nmode = \"standalone\"\n[runtime]\nsandbox = \"podman\"\n",
		"unknown sandbox":         "[runtime]\nsandbox = \"docker\"\n",
		"image without digest":    "[runtime]\nimage = \"docker.io/library/alpine:3\"\n",
		"relative podman":         "[runtime]\npodman = \"podman\"\n",
		"tiny memory":             "[runtime]\nmemory_bytes = 1024\n",
		"monitor too slow":        "[runtime]\nmonitor_interval = \"1m\"\n",
		"unknown alias":           "[[runtime.server]]\nalias = \"nope\"\n",
		"duplicate alias":         "[[runtime.server]]\nalias = \"fs\"\n[[runtime.server]]\nalias = \"fs\"\n",
		"session scope":           "[[runtime.server]]\nalias = \"fs\"\nscope = \"session\"\n",
		"bad network":             "[[runtime.server]]\nalias = \"fs\"\nnetwork = \"host\"\n",
		"relative target":         "[[runtime.server]]\nalias = \"fs\"\n[[runtime.server.mount]]\nsource = \"/a\"\ntarget = \"rel\"\n",
		"duplicate target":        "[[runtime.server]]\nalias = \"fs\"\n[[runtime.server.mount]]\nsource = \"/a\"\ntarget = \"/x\"\n[[runtime.server.mount]]\nsource = \"/b\"\ntarget = \"/x\"\n",
		"unknown key":             "[runtime]\nprivileged = true\n",
		"server image no digest":  "[[runtime.server]]\nalias = \"fs\"\nimage = \"x:latest\"\n",
		"bad user":                "[runtime]\nuser = \"root\"\n",
		"bad deviation action":    "[[runtime.server]]\nalias = \"fs\"\non_deviation = \"ignore\"\n",
		"unknown cgroup manager":  "[runtime]\ncgroup_manager = \"none\"\n",
		"userns size out of band": "[runtime]\nuserns_size = 10\n",
	} {
		if _, err := Parse([]byte(withBefore(extra))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(withBefore("[runtime]\nimage = \"registry.local/srv" + digest + "\"\n"))); err != nil {
		t.Errorf("digest image refused: %v", err)
	}
}

func TestRuntimeRelativeMountResolved(t *testing.T) {
	dir := t.TempDir()
	body := withBefore("[[runtime.server]]\nalias = \"fs\"\n[[runtime.server.mount]]\nsource = \"data\"\n")
	p := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Runtime.FindServer("fs").Mounts[0]
	if m.Source != filepath.Join(dir, "data") || m.Target != "" {
		t.Fatalf("mount %+v", m)
	}
}
