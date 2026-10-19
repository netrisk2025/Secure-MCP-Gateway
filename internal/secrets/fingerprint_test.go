package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestFingerprintsDetectEncodedForms(t *testing.T) {
	// E-29 registration: analytics.TestSecretFingerprintsRegisteredWithCollector;
	// its wiring in cmd/smcpd is not exercised by a test.
	reqtest.Partial(t, "FR-6.10")
	value := []byte("sk-live-4f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c?&/=+")
	fp := NewFingerprints()
	fp.Register("sec_1", 2, value)
	s := string(value)
	cases := map[string]string{
		"raw":              "result: " + s + " done",
		"fragment-12":      "partial " + s[5:17] + " leak",
		"base64":           "token=" + base64.StdEncoding.EncodeToString(value),
		"base64-offset-1":  base64.StdEncoding.EncodeToString(append([]byte("x"), value...)),
		"base64-offset-2":  base64.StdEncoding.EncodeToString(append([]byte("xy"), value...)),
		"base64url-offset": base64.URLEncoding.EncodeToString(append([]byte("Authorization: Bearer "), value...)),
		"hex":              hex.EncodeToString(value),
		"HEX":              strings.ToUpper(hex.EncodeToString(value)),
		"query":            "https://x.example/?k=" + url.QueryEscape(s),
		"path":             "/p/" + url.PathEscape(s),
	}
	for name, text := range cases {
		ms := fp.Scan([]byte(text))
		if len(ms) == 0 {
			t.Errorf("%s: not detected in %q", name, text)
			continue
		}
		if ms[0].SecretRef != "sec_1" || ms[0].Version != 2 {
			t.Errorf("%s: match %+v", name, ms[0])
		}
	}
	for _, clean := range []string{"", "hello world, nothing to see", s[:11], strings.Repeat("a", 4096)} {
		if ms := fp.Scan([]byte(clean)); len(ms) != 0 {
			t.Errorf("false positive on %q: %+v", clean, ms)
		}
	}
}

func TestFingerprintsShortValueAndRedaction(t *testing.T) {
	reqtest.Partial(t, "FR-6.10", "SR-6.7-1")
	fp := NewFingerprints()
	fp.Register("sec_short", 1, []byte("pin12345")) // 8 bytes, below the window
	fp.Register("sec_long", 1, []byte("a-much-longer-secret-value-0001"))
	if ms := fp.Scan([]byte("code pin12345 used")); len(ms) != 1 || ms[0].SecretRef != "sec_short" {
		t.Fatalf("short value: %+v", ms)
	}
	in := "x a-much-longer-secret-value-0001 y pin12345 z"
	out, ms := fp.Redact([]byte(in))
	if len(ms) != 2 {
		t.Fatalf("matches %+v", ms)
	}
	if got := string(out); got != "x [REDACTED:sec_long] y [REDACTED:sec_short] z" {
		t.Fatalf("redacted %q", got)
	}
	if fp.RedactString("clean") != "clean" {
		t.Fatal("clean text changed")
	}
}

func TestFingerprintSetHoldsNoPlaintext(t *testing.T) {
	reqtest.Partial(t, "FR-6.10")
	value := "plaintext-secret-value-xyz-123"
	fp := NewFingerprints()
	fp.Register("sec_1", 1, []byte(value))
	fp.Register("sec_1", 1, []byte(value)) // idempotent
	dump := fmt.Sprintf("%v %v", fp.set, fp.short)
	for _, w := range []string{value, value[:12], base64.StdEncoding.EncodeToString([]byte(value))[:12], hex.EncodeToString([]byte(value))[:12]} {
		if strings.Contains(dump, w) {
			t.Fatalf("fingerprint set holds %q", w)
		}
	}
	if fp.Len() == 0 {
		t.Fatal("nothing registered")
	}
}

func BenchmarkScan64KiB(b *testing.B) {
	fp := NewFingerprints()
	fp.Register("sec_1", 1, []byte("benchmark-secret-value-000000"))
	data := []byte(strings.Repeat("lorem ipsum dolor sit amet ", 64<<10/27))
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		fp.Scan(data)
	}
}
