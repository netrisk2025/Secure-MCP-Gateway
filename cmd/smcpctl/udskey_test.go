package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestUDSKey: smcpctl uds key writes a new bearer key of 32 random bytes
// to a 0600 file, refuses to overwrite one, and prints only the Argon2id
// verifier for the configuration (SR-2.3-1, which is verified by
// inspection; docs/verification/inspections.md).
func TestUDSKey(t *testing.T) {
	reqtest.Partial(t, "SR-2.3-1")
	dir := t.TempDir()
	seen := map[string]bool{}
	for i := range 2 {
		p := filepath.Join(dir, "key"+strconv.Itoa(i))
		var out, errb bytes.Buffer
		if code := run([]string{"uds", "key", "--out", p}, &out, &errb); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("key file: %v %v", st, err)
		}
		raw, _ := os.ReadFile(p)
		key := strings.TrimSpace(string(raw))
		if b, err := base64.RawURLEncoding.DecodeString(key); err != nil || len(b) != 32 {
			t.Fatalf("key is not 256 bits: %q %v", key, err)
		}
		if seen[key] {
			t.Fatal("two runs produced the same key")
		}
		seen[key] = true
		line := strings.TrimSpace(out.String())
		hash, ok := strings.CutPrefix(line, "key_hash = ")
		if !ok {
			t.Fatalf("output %q", line)
		}
		hash, _ = strconv.Unquote(hash)
		if strings.Contains(out.String(), key) || !strings.HasPrefix(hash, "$argon2id$") || !keys.VerifyPassword(hash, key) {
			t.Fatalf("output is not the key's verifier: %q", line)
		}
		if code := run([]string{"uds", "key", "--out", p}, &out, &errb); code == 0 {
			t.Fatal("an existing key file was overwritten")
		}
	}
}
