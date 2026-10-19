package filters

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestRegisterBytesForms: the byte-slice forms are exactly the FR-6.10
// forms (raw, four Base64 variants, lower and upper hex, query and path
// escaping), a value registered from bytes is detected in each form, the
// caller's slice is left unchanged, and the encoded buffers are
// overwritten afterwards (SR-2.13-2: no immutable copy of a delivered
// value is made to fingerprint it).
func TestRegisterBytesForms(t *testing.T) {
	reqtest.Partial(t, "FR-6.10")
	for _, v := range []string{"s3cr3t-Value-0123456789-abcdef", "p@ss w/rd+$&:=?;,#%~é", "\x00\xff\x10binary-secret-bytes!"} {
		want := []string{v,
			base64.StdEncoding.EncodeToString([]byte(v)), base64.RawStdEncoding.EncodeToString([]byte(v)),
			base64.URLEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)),
			hex.EncodeToString([]byte(v)), strings.ToUpper(hex.EncodeToString([]byte(v))),
			url.QueryEscape(v), url.PathEscape(v)}
		got := encodedFormsBytes([]byte(v))
		if len(got) != len(want) {
			t.Fatalf("%d forms", len(got))
		}
		for i := range want {
			if string(got[i]) != want[i] {
				t.Fatalf("%q form %d: %q, want %q", v, i, got[i], want[i])
			}
		}
		set := NewFingerprintSet()
		value := []byte(v)
		set.RegisterBytes("vault:x@1", value)
		if string(value) != v {
			t.Fatal("RegisterBytes changed the caller's value")
		}
		for _, form := range want[1:] {
			if _, ok := set.Match("prefix " + form + " suffix"); !ok && len(form) >= FingerprintWindow {
				t.Fatalf("%q form %q not detected", v, form)
			}
		}
	}
	// The derived buffers are cleared once fingerprinted.
	forms := encodedFormsBytes([]byte("another-secret-value-123"))
	set := NewFingerprintSet()
	set.registerForms("r", forms)
	for i, b := range forms[1:] {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("form %d not overwritten: %q", i+1, b)
		}
	}
}
