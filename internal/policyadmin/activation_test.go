package policyadmin

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// copyTree copies a state directory as a crash would leave it on disk.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(out, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, info.Mode().Perm()|0o200)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// orderGW records, at the moment the decider is asked to swap, which
// revision the policy-control record on disk names.
type orderGW struct {
	*fakeGW
	store   *policystore.Store
	onDisk  []string
	swapped []string
}

func (g *orderGW) ActivatePolicy(actor string, s *policy.Snapshot) (bool, error) {
	rev, _, err := g.store.Active()
	if err != nil {
		g.onDisk = append(g.onDisk, "error: "+err.Error())
	} else {
		g.onDisk = append(g.onDisk, rev.Record.Revision)
	}
	g.swapped = append(g.swapped, s.Revision)
	return g.fakeGW.ActivatePolicy(actor, s)
}

// TestActivationCrashAtEachStep is SR-1.15-1. The E-06 half: the decider
// is asked to swap only after the new control record is in place (renamed
// and the directory flushed, which Activate completes before returning),
// and never when the record cannot be written. The E-05 half: the state
// directory is reproduced as a crash at each step of activation would
// leave it (before the temporary file, temporary file partly written,
// temporary file complete but not renamed, renamed), and a restart loads
// either the old or the new revision, never a mixture; a control record
// torn in place, which the rename never produces, fails closed instead of
// loading anything.
func TestActivationCrashAtEachStep(t *testing.T) {
	reqtest.Verifies(t, "SR-1.15-1")
	f := newFixture(t)
	g := &orderGW{fakeGW: f.gw, store: f.store}
	f.svc.Bind(g)

	// Swap order: the record names r2 before the decider swaps to r2.
	if _, err := f.svc.Publish(rev("r2"), PublishOptions{Actor: "a"}); err != nil {
		t.Fatal(err)
	}
	if len(g.swapped) != 1 || g.swapped[0] != "r2" || g.onDisk[0] != "r2" {
		t.Fatalf("decider swapped to %v while the record named %v", g.swapped, g.onDisk)
	}
	// The control record cannot be written: no swap, r2 stays active.
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		pdir := filepath.Join(f.dir, "policy")
		if err := os.Chmod(pdir, 0o500); err != nil {
			t.Fatal(err)
		}
		_, err := f.svc.Publish(rev("r3"), PublishOptions{Actor: "a"})
		_ = os.Chmod(pdir, 0o700)
		if !errors.Is(err, ErrActivation) || len(g.swapped) != 1 || f.gw.snapshot().Revision != "r2" {
			t.Fatalf("unwritable control record: %v, swaps %v, decider %s", err, g.swapped, f.gw.snapshot().Revision)
		}
	}

	// Crash states. before: r4 stored (Put precedes Activate), r2 active.
	r4, _, err := f.store.Put(rev("r4"), policystore.Meta{Actor: "a"})
	if err != nil {
		t.Fatal(err)
	}
	before := t.TempDir()
	copyTree(t, f.dir, before)
	if _, err := f.store.Activate(r4, "a"); err != nil {
		t.Fatal(err)
	}
	newCtl, err := os.ReadFile(filepath.Join(f.dir, policystore.ControlFile))
	if err != nil {
		t.Fatal(err)
	}
	ctl := filepath.FromSlash(policystore.ControlFile)
	tmpName := filepath.Join(filepath.Dir(ctl), "."+filepath.Base(ctl)+".tmp-crash")
	for _, c := range []struct {
		step  string
		files map[string][]byte
		want  string // revision loaded; "" means fail closed
	}{
		{"before the temporary file", nil, "r2"},
		{"temporary file partly written", map[string][]byte{tmpName: newCtl[:len(newCtl)/2]}, "r2"},
		{"temporary file flushed, not renamed", map[string][]byte{tmpName: newCtl}, "r2"},
		{"renamed", map[string][]byte{ctl: newCtl}, "r4"},
		{"record torn in place", map[string][]byte{ctl: newCtl[:len(newCtl)/2]}, ""},
	} {
		dir := t.TempDir()
		copyTree(t, before, dir)
		for name, b := range c.files {
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		st, err := policystore.Open(dir)
		if err != nil {
			t.Fatalf("%s: %v", c.step, err)
		}
		snap, imported, fault, err := Load(st, filepath.Join(dir, "policy.json"))
		switch {
		case c.want == "":
			if snap != nil || fault != FaultSignature || err == nil {
				t.Fatalf("%s: loaded %v (fault %q, %v)", c.step, snap, fault, err)
			}
		case err != nil || imported != nil || snap == nil || snap.Revision != c.want:
			t.Fatalf("%s: %v %v %q %v, want %s", c.step, snap, imported, fault, err, c.want)
		default:
			// Never mixed: the loaded snapshot is the stored revision's own content.
			r, _ := st.Get(c.want)
			if r.Snapshot.Digest != snap.Digest {
				t.Fatalf("%s: snapshot digest %s, revision %s", c.step, snap.Digest, r.Snapshot.Digest)
			}
		}
	}
}
