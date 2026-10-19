package secrets

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestFingerprintsOnRegister: each secret version reaches the registered
// sinks once, when it is first fingerprinted.
func TestFingerprintsOnRegister(t *testing.T) {
	reqtest.Partial(t, "FR-6.10")
	f := NewFingerprints()
	type got struct {
		ref     string
		version int
		value   string
	}
	var seen []got
	f.OnRegister(func(ref string, version int, value []byte) { seen = append(seen, got{ref, version, string(value)}) })
	f.Register("api", 1, []byte("value-one-0123456789"))
	f.Register("api", 1, []byte("value-one-0123456789"))
	f.Register("api", 2, []byte("value-two-0123456789"))
	if len(seen) != 2 || seen[0] != (got{"api", 1, "value-one-0123456789"}) || seen[1].version != 2 {
		t.Fatalf("%+v", seen)
	}
}
