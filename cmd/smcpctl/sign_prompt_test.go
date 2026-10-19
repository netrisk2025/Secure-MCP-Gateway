package main

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// withTerminal runs smcpctl with its standard input on a pseudo-terminal
// (through script(1)) and types input into it.
func withTerminal(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	bin := filepath.Join(binDir, "smcpctl")
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("script", append([]string{"-q", "/dev/null", bin}, args...)...)
	case "linux":
		quoted := []string{shellQuote(bin)}
		for _, a := range args {
			quoted = append(quoted, shellQuote(a))
		}
		cmd = exec.Command("script", "-qec", strings.Join(quoted, " "), "/dev/null")
	default:
		t.Skip("no script(1) on " + runtime.GOOS)
	}
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) not installed")
	}
	pr, pw := ioPipe(t)
	cmd.Stdin = pr
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Type the input once the prompt is up; keep stdin open until the
	// command exits, as a person at a terminal would.
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for !strings.Contains(out.String(), "Passphrase") && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		_, _ = pw.Write([]byte(input))
	}()
	err := cmd.Wait()
	pw.Close()
	return out.String(), err
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// lockedBuffer is a bytes.Buffer safe for one writer and concurrent readers.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// TestPackageSigningKeySources is FR-14.6: `smcpctl package sign` signs the
// package index with a passphrase-protected minisign key read from a file,
// with the passphrase from a file and, separately, typed at an interactive
// prompt (a pseudo-terminal), and both signatures verify; a key or a
// passphrase given as a command-line argument is refused.
func TestPackageSigningKeySources(t *testing.T) {
	reqtest.Verifies(t, "FR-14.6")
	work := t.TempDir()
	key := pkgtest.NewKey(t)
	const pass = "correct horse battery"
	// Low scrypt cost for the test; keygen uses minisign's 1 GiB cost.
	sec, err := packaging.EncryptSecretKeyCost(pass, key.Private, 1<<15, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := writeFile(t, work, "op.key", string(sec))
	pubFile := writeFile(t, work, "op.pub", string(key.Public))
	passFile := writeFile(t, work, "pass", pass+"\n")
	fileSigned, prompted := filepath.Join(work, "a"), filepath.Join(work, "b")
	pkgtest.Build(t, fileSigned, pkgtest.Spec{ID: "sig-a", Revision: "1"})
	pkgtest.Build(t, prompted, pkgtest.Spec{ID: "sig-b", Revision: "1"})

	mustCtl(t, "package", "sign", fileSigned, "--key", keyFile, "--passphrase-file", passFile)
	if out := mustCtl(t, "package", "verify", fileSigned, "--pubkey", pubFile); !strings.Contains(out, "package OK") {
		t.Fatalf("file passphrase: %s", out)
	}
	if out, err := withTerminal(t, pass+"\n", "package", "sign", prompted, "--key", keyFile); err != nil {
		t.Fatalf("prompted signing: %v\n%s", err, out)
	}
	if out := mustCtl(t, "package", "verify", prompted, "--pubkey", pubFile); !strings.Contains(out, "package OK") {
		t.Fatalf("prompted passphrase: %s", out)
	}
	// Without a terminal and without a passphrase file, signing refuses.
	if out, err := ctl(t, "", "package", "sign", prompted, "--key", keyFile); err == nil {
		t.Fatalf("signed without a passphrase source: %s", out)
	}
	for _, args := range [][]string{
		{"package", "sign", fileSigned, "--secret-key", "RWQ..."},
		{"package", "sign", fileSigned, "--key", keyFile, "--passphrase", pass},
	} {
		if out, err := ctl(t, "", args...); err == nil || !strings.Contains(out, packaging.ReasonKeyOnCommandLine) {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
}
