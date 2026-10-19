//go:build unix

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// Crash-consistency test of the intent commit (SR-6.2-1). A child process
// (this test binary) runs the Gateway with a real Evidence Journal whose
// segment files go through a fault-injecting file layer, makes calls one
// after another, and is killed with SIGKILL at a chosen write point of the
// journal. The parent then restarts the journal (crash recovery), verifies
// it as `smcpctl journal verify` does, and checks that every launch the
// backend saw has its intent record in the journal.
const (
	crashChildEnv = "SMCP_CRASH_CHILD"
	crashCalls    = 3
)

// crashSeed is the evidence key seed shared by parent and child.
var crashSeed = bytes.Repeat([]byte{7}, ed25519.SeedSize)

// faultLayer counts the journal's segment-file operations and kills the
// process at one of them. Written bytes are held in memory until Sync, the
// way a disk cache holds them until a flush, so a kill loses everything
// not yet flushed; "during" a flush writes only the first half of the
// pending bytes before the kill (a torn append).
type faultLayer struct {
	ops   atomic.Int64
	at    int64  // operation to fail at; 0 never
	mode  string // before, during, after
	mu    sync.Mutex
	kinds []byte // 'w' write, 's' sync, per operation
}

func (fl *faultLayer) open(path string) (audit.SegmentFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // test journal
	if err != nil {
		return nil, err
	}
	return &faultFile{f: f, fl: fl}, nil
}

func (fl *faultLayer) step(kind byte) (int64, bool) {
	n := fl.ops.Add(1)
	fl.mu.Lock()
	fl.kinds = append(fl.kinds, kind)
	fl.mu.Unlock()
	return n, n == fl.at
}

func die() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {}
}

type faultFile struct {
	f   *os.File
	fl  *faultLayer
	buf []byte
}

func (ff *faultFile) Write(b []byte) (int, error) {
	_, hit := ff.fl.step('w')
	if hit && ff.fl.mode == "before" {
		die()
	}
	ff.buf = append(ff.buf, b...)
	if hit {
		die()
	}
	return len(b), nil
}

func (ff *faultFile) Sync() error {
	_, hit := ff.fl.step('s')
	if hit && ff.fl.mode == "before" {
		die()
	}
	if hit && ff.fl.mode == "during" {
		_, _ = ff.f.Write(ff.buf[:len(ff.buf)/2])
		die()
	}
	if _, err := ff.f.Write(ff.buf); err != nil {
		return err
	}
	ff.buf = ff.buf[:0]
	err := ff.f.Sync()
	if hit {
		die()
	}
	return err
}

func (ff *faultFile) Close() error {
	if len(ff.buf) > 0 {
		if _, err := ff.f.Write(ff.buf); err != nil {
			return err
		}
		ff.buf = nil
	}
	return ff.f.Close()
}

// TestCrashChild is the child process; it does nothing unless started by
// TestIntentCrashConsistency.
func TestCrashChild(t *testing.T) {
	if os.Getenv(crashChildEnv) != "1" {
		t.Skip("child process of TestIntentCrashConsistency")
	}
	dir := os.Getenv("SMCP_CRASH_DIR")
	at, _ := strconv.ParseInt(os.Getenv("SMCP_CRASH_AT"), 10, 64)
	fl := &faultLayer{at: at, mode: os.Getenv("SMCP_CRASH_MODE")}
	j, err := audit.Open(filepath.Join(dir, "journal"), ed25519.NewKeyFromSeed(crashSeed), audit.Options{MaxEvents: 5, OpenSegment: fl.open})
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "launches")
	backend := func() *mcp.Server {
		s := mcp.NewServer(&mcp.Implementation{Name: "crash-backend", Version: "1"}, nil)
		mcp.AddTool(s, &mcp.Tool{Name: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, a struct {
			Text string `json:"text"`
		}) (*mcp.CallToolResult, any, error) {
			// The launch: recorded durably before the tool acts.
			f, err := os.OpenFile(marker, os.O_CREATE|os.O_APPEND|os.O_WRONLY|os.O_SYNC, 0o600) //nolint:gosec // test marker
			if err != nil {
				return nil, nil, err
			}
			_, _ = fmt.Fprintln(f, "launch", a.Text)
			_ = f.Close()
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + a.Text}}}, nil, nil
		})
		return s
	}
	h := newHarness(t, harnessOpts{backend: backend, evidence: j, evidenceErr: j.Err})
	_, tok := h.session("ro")
	cs := h.client(tok)
	for i := range crashCalls {
		_, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": fmt.Sprint("call-", i)}})
	}
	fl.mu.Lock()
	fmt.Printf("CRASHCHILD ops=%d kinds=%s\n", fl.ops.Load(), fl.kinds)
	fl.mu.Unlock()
}

type crashRun struct {
	ops    int64
	kinds  string
	killed bool
	output string
}

func runCrashChild(t *testing.T, dir string, at int64, mode string) crashRun {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCrashChild$", "-test.v", "-test.count=1") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), crashChildEnv+"=1", "SMCP_CRASH_DIR="+dir, fmt.Sprintf("SMCP_CRASH_AT=%d", at), "SMCP_CRASH_MODE="+mode)
	out, err := cmd.CombinedOutput()
	r := crashRun{output: string(out)}
	if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			r.killed = true
		}
	}
	sc := bufio.NewScanner(strings.NewReader(r.output))
	for sc.Scan() {
		if _, rest, ok := strings.Cut(sc.Text(), "CRASHCHILD ops="); ok {
			n, kinds, _ := strings.Cut(rest, " kinds=")
			r.ops, _ = strconv.ParseInt(n, 10, 64)
			r.kinds = kinds
		}
	}
	if !r.killed && r.ops == 0 {
		t.Fatalf("child at %d/%s neither finished nor was killed: %v\n%s", at, mode, err, out)
	}
	return r
}

// checkRestart reopens the journal (crash recovery), verifies it, and
// compares the launches with the intent records. It returns the intent
// records.
func checkRestart(t *testing.T, dir, label string) []audit.Event {
	t.Helper()
	jdir := filepath.Join(dir, "journal")
	key := ed25519.NewKeyFromSeed(crashSeed)
	j, err := audit.Open(jdir, key, audit.Options{MaxEvents: 5})
	if err != nil {
		t.Fatalf("%s: restart: %v", label, err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("%s: close: %v", label, err)
	}
	if _, err := audit.Verify(jdir, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("%s: journal verify after restart: %v", label, err)
	}
	segs, err := audit.Segments(jdir)
	if err != nil {
		t.Fatal(err)
	}
	var intents []audit.Event
	for _, s := range segs {
		if _, err := audit.ScanSegment(jdir, s, func(e audit.Event) error {
			if e.Class == "decision" && e.Phase == audit.PhaseAuthorized && e.Outcome == "permit" {
				intents = append(intents, e)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	launches := 0
	if b, err := os.ReadFile(filepath.Join(dir, "launches")); err == nil {
		launches = strings.Count(string(b), "launch ")
	}
	// Calls are made one after another, so the n-th launch happened only
	// after the n-th intent's flush returned.
	if launches > len(intents) {
		t.Fatalf("%s: %d launches but only %d intent records survived the crash", label, launches, len(intents))
	}
	return intents
}

// TestIntentCrashConsistency is SR-6.2-1. The decision, the invocation
// intent and the IDs of the decisive rule, server revision, tool revision,
// filters, audit profile and observation profile are one journal record
// (the authorized decision event); the launch capability is issued only
// after that record's flush returns. The child process is killed before,
// during (torn flush) and after every write and flush of the journal's
// segment files over three calls, including segment rotation (footer,
// next header); after each kill the journal recovers, verifies, and no
// launch exists whose intent record is missing.
func TestIntentCrashConsistency(t *testing.T) {
	reqtest.Verifies(t, "SR-6.2-1")
	if os.Getenv(crashChildEnv) == "1" {
		t.Skip("in the child")
	}
	base := runCrashChild(t, t.TempDir(), 0, "")
	if base.killed || base.ops == 0 || int64(len(base.kinds)) != base.ops {
		t.Fatalf("baseline run: %+v", base)
	}
	if !strings.Contains(base.kinds, "s") {
		t.Fatalf("baseline run made no flush: %s", base.kinds)
	}
	// The baseline's intent records carry every ID the requirement names.
	baseDir := t.TempDir()
	if r := runCrashChild(t, baseDir, 0, ""); r.killed {
		t.Fatal("second baseline killed")
	}
	intents := checkRestart(t, baseDir, "baseline")
	if len(intents) != crashCalls {
		t.Fatalf("baseline: %d intent records, want %d", len(intents), crashCalls)
	}
	for _, e := range intents {
		d, _ := e.Detail.(map[string]any)
		ob, _ := d["obligations"].(map[string]any)
		rules, _ := d["decisive_rules"].([]any)
		if e.DecisionID == "" || e.CorrelationID == "" || e.ServerRevision == "" || e.ToolRevision == "" || e.PolicyRevision == "" || len(rules) == 0 || ob == nil {
			t.Fatalf("intent record lacks an ID: %+v", e)
		}
		for _, k := range []string{"filters", "audit_profile", "observation_policy"} {
			if _, ok := ob[k]; !ok {
				t.Fatalf("intent record obligations lack %s: %v", k, ob)
			}
		}
	}

	type point struct {
		at   int64
		mode string
	}
	var points []point
	for i, k := range base.kinds {
		at := int64(i + 1)
		points = append(points, point{at, "before"}, point{at, "after"})
		if k == 's' {
			points = append(points, point{at, "during"})
		}
	}
	sem := make(chan struct{}, 4)
	var killed atomic.Int64
	t.Run("points", func(t *testing.T) {
		for _, p := range points {
			t.Run(fmt.Sprintf("%d-%s", p.at, p.mode), func(t *testing.T) {
				t.Parallel()
				sem <- struct{}{}
				defer func() { <-sem }()
				dir := t.TempDir()
				r := runCrashChild(t, dir, p.at, p.mode)
				if r.killed {
					killed.Add(1)
				}
				checkRestart(t, dir, fmt.Sprintf("kill at op %d %s", p.at, p.mode))
			})
		}
	})
	if killed.Load() < int64(len(points))/2 {
		t.Fatalf("only %d of %d runs reached their kill point", killed.Load(), len(points))
	}
}
