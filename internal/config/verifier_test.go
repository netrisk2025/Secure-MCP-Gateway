package config

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestPasswordVerifierStrength is SR-2.7-1: every configured password
// and client secret verifier must carry at least the CP-28 Argon2id
// parameters (64 MiB, t = 3, p = 1); weaker ones are refused at load, and
// the verifiers the Gateway writes itself (keys.HashPassword, used by
// bootstrap, hash-password, admin redeem and principal credentials) carry
// exactly CP-28.
func TestPasswordVerifierStrength(t *testing.T) {
	reqtest.Verifies(t, "SR-2.7-1")
	h, err := keys.HashPassword("a password for the test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=1$") || keys.CheckVerifier(h) != nil {
		t.Fatalf("generated verifier %s", h)
	}
	const salt = "$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA"
	weak := map[string]string{
		"memory":      "$argon2id$v=19$m=19456,t=3,p=1" + salt,
		"iterations":  "$argon2id$v=19$m=65536,t=2,p=1" + salt,
		"parallelism": "$argon2id$v=19$m=65536,t=3,p=0" + salt,
		"version":     "$argon2id$v=16$m=65536,t=3,p=1" + salt,
		"unparsable":  "$argon2id$v=19$m=lots" + salt,
		"over bound":  "$argon2id$v=19$m=1048576,t=3,p=1" + salt,
	}
	places := map[string]func(hash string) string{
		"admin": func(hash string) string { return strings.Replace(good, goodHash, hash, 1) },
		"approver": func(hash string) string {
			return withBefore("[[approver]]\nusername = \"sam\"\npassword_hash = \"" + hash + "\"\n")
		},
		"approvals account": func(hash string) string {
			return withBefore("[[approvals.account]]\nusername = \"alice\"\npassword_hash = \"" + hash + "\"\n")
		},
		"console account": func(hash string) string {
			return withBefore("[[console.account]]\nusername = \"olga\"\npassword_hash = \"" + hash + "\"\nrole = \"operator\"\n")
		},
		"client secret": func(hash string) string {
			return strings.Replace(good, `client_id = "cid"`, `client_id = "cid"`+"\nclient_secret_hash = \""+hash+"\"", 1)
		},
	}
	for place, build := range places {
		if _, err := Parse([]byte(build(h))); err != nil {
			t.Fatalf("%s with a CP-28 verifier: %v", place, err)
		}
		for name, hash := range weak {
			if _, err := Parse([]byte(build(hash))); err == nil || !strings.Contains(err.Error(), "argon2id") {
				t.Fatalf("%s accepted a verifier with a weak or invalid %s: %v", place, name, err)
			}
		}
	}
	// Stronger parameters within the verification bounds are accepted.
	if _, err := Parse([]byte(places["admin"]("$argon2id$v=19$m=131072,t=4,p=2" + salt))); err != nil {
		t.Fatal(err)
	}
}
