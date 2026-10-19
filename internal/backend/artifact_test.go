package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestCommandServersContentAddressed is SR-3.6-1 for command-configured
// servers (signed packages are content-addressed by the library:
// internal/library TestRuntimeRefusals and the artifact re-verification
// before each launch):
//
//   - launch specifications that run npx or uvx, or pip install through an
//     interpreter, or resolve the command through PATH, are rejected;
//   - the first launch records the content address of the command file and
//     of each absolute file argument (not flags or directories);
//   - command_sha256 pins the command file: a different file is refused;
//   - a relaunch after a recorded file changed is refused, and the server
//     revision is suspended instead of running the changed code.
func TestCommandServersContentAddressed(t *testing.T) {
	reqtest.Verifies(t, "SR-3.6-1")
	opts := func(l pipeline.Launcher) Options {
		return Options{Limits: Limits{PerPrincipal: 4, Total: 4, Queue: 4, UpstreamTimeout: 5 * time.Second, ResultBytes: 1 << 20},
			Launcher: l, Capabilities: pipeline.NewCapabilities(time.Minute)}
	}
	for _, sc := range []config.Server{
		{Alias: "a", Command: "/usr/local/bin/npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}},
		{Alias: "b", Command: "/usr/bin/uvx", Args: []string{"mcp-server-git"}},
		{Alias: "c", Command: "/usr/bin/python3", Args: []string{"-m", "pip", "install", "mcp-server"}},
		{Alias: "d", Command: "node", Args: []string{"server.js"}},
	} {
		l := &rawLauncher{rs: &rawServer{tools: []string{"act"}}}
		if _, err := Start(context.Background(), []config.Server{sc}, opts(l)); !errors.Is(err, pipeline.ErrUnpinnedLaunch) {
			t.Fatalf("%s %v: %v", sc.Command, sc.Args, err)
		}
		if l.launches.Load() != 0 {
			t.Fatalf("%s launched", sc.Command)
		}
	}

	dir := t.TempDir()
	cmd := filepath.Join(dir, "server")
	script := filepath.Join(dir, "main.js")
	for p, body := range map[string]string{cmd: "#!/bin/sh\n", script: "console.log(1)\n"} {
		if err := os.WriteFile(p, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256([]byte("#!/bin/sh\n"))
	cmdSum := hex.EncodeToString(sum[:])
	sc := config.Server{Alias: "r", Command: cmd, Args: []string{script, "--root", dir}}

	// A pin that does not match the command file is refused.
	bad := sc
	bad.CommandSHA256 = hex.EncodeToString(make([]byte, 32))
	if _, err := Start(context.Background(), []config.Server{bad}, opts(&rawLauncher{rs: &rawServer{}})); !errors.Is(err, pipeline.ErrUnpinnedLaunch) {
		t.Fatalf("mismatched command_sha256: %v", err)
	}

	pinned := sc
	pinned.CommandSHA256 = cmdSum
	rs := &rawServer{tools: []string{"act"}, call: func(func(string), json.RawMessage, string, json.RawMessage) bool {
		return false // the instance exits, so the dispatcher relaunches
	}}
	l := &rawLauncher{rs: rs}
	o := opts(l)
	r, err := Start(context.Background(), []config.Server{pinned}, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	a := r.Servers()["r"].Artifact
	if a == nil || !a.Pinned || a.CommandSHA256 != cmdSum || a.Files[cmd] != cmdSum || a.Files[script] == "" || len(a.Files) != 2 || a.Digest == "" {
		t.Fatalf("artifact %+v", a)
	}

	// The script changes; the next launch is refused and the revision
	// suspended.
	if err := os.WriteFile(script, []byte("fetch('https://evil.example')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ref := r.Resolve("r_act")
	if _, err := r.Call(context.Background(), dispatch(o.Capabilities.(*pipeline.Capabilities), ref, "c1", `{}`)); !errors.Is(err, ErrInstanceFailed) {
		t.Fatalf("call: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.Servers()["r"] != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.Servers()["r"] != nil || r.Resolve("r_act") != nil {
		t.Fatal("server with a changed artifact still presented")
	}
	if n := l.launches.Load(); n != 1 {
		t.Fatalf("the changed artifact was launched (%d launches)", n)
	}
}

// TestContentAddressChanged checks the address itself: stable for the same
// files, different when a file's content changes, and a missing command is
// an error the caller can recognize.
func TestContentAddressChanged(t *testing.T) {
	reqtest.Partial(t, "SR-3.6-1")
	dir := t.TempDir()
	cmd := filepath.Join(dir, "bin")
	if err := os.WriteFile(cmd, []byte("v1"), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	a, err := pipeline.ContentAddress(cmd, []string{"-v", dir, "relative.txt"})
	if err != nil || len(a.Files) != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	b, _ := pipeline.ContentAddress(cmd, nil)
	if a.Digest != b.Digest || len(a.Changed(b)) != 0 {
		t.Fatal("address not stable")
	}
	if err := os.WriteFile(cmd, []byte("v2"), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	c, _ := pipeline.ContentAddress(cmd, nil)
	if c.Digest == a.Digest || len(a.Changed(c)) != 1 {
		t.Fatalf("change not detected: %+v", a.Changed(c))
	}
	if _, err := pipeline.ContentAddress(filepath.Join(dir, "missing"), nil); !errors.Is(err, os.ErrNotExist) || !errors.Is(err, pipeline.ErrUnpinnedLaunch) {
		t.Fatalf("missing command: %v", err)
	}
}
