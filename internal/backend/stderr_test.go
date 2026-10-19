package backend

import (
	"strings"
	"testing"
)

// A server that prints its environment before failing the handshake must
// not put its delivered secret values, or megabytes of output, into the
// start error that reaches the logs.
func TestStderrForErrorBoundsAndRedacts(t *testing.T) {
	secret := "s3cr3t-api-key-value"
	long := strings.Repeat("x", 1<<20) + "API_KEY=" + secret + "\nfatal: bad handshake"
	got := stderrForError(long, map[string]string{"API_KEY": secret, "SHORT": "ab"})
	if strings.Contains(got, secret) {
		t.Fatalf("secret value in error text: %q", got)
	}
	if !strings.Contains(got, "API_KEY=[REDACTED]") || !strings.HasSuffix(got, "fatal: bad handshake") {
		t.Fatalf("tail not kept: %q", got[len(got)-80:])
	}
	if len(got) > stderrTailBytes+8 {
		t.Fatalf("error text is %d bytes, want at most about %d", len(got), stderrTailBytes)
	}
	// A secret cut by the bound leaves no fragment: redaction runs first.
	cut := secret + strings.Repeat("y", stderrTailBytes-4)
	if got := stderrForError(cut, map[string]string{"K": secret}); strings.Contains(got, secret[len(secret)-6:]) {
		t.Fatalf("fragment of a secret survived the cut: %q", got[:40])
	}
}
