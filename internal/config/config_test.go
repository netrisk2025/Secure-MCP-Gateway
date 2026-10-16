package config

import (
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const good = `
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA"
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = "cid"
principal = "cc"
redirect_uris = ["http://localhost:*/cb"]
[[server]]
alias = "fs"
command = "npx"
`

func TestDefaultsAndSchema(t *testing.T) {
	reqtest.Verifies(t, "FR-12.6")
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listener.Address != "127.0.0.1:8443" || cfg.ResourceURI() != "https://127.0.0.1:8443/mcp" {
		t.Fatalf("%+v", cfg.Listener)
	}
	l := cfg.Limits
	if l.RequestBodyBytes != 1<<20 || l.ResultBytes != 8<<20 || l.ToolConcurrencyPerUser != 4 || l.ToolConcurrencyTotal != 16 || l.ToolQueue != 32 ||
		l.PrincipalCallsPerMin != 60 || l.UpstreamTimeout.Duration != 45*time.Second || l.ClientDeadline.Duration != 60*time.Second ||
		l.SessionMaxLifetime.Duration != 8*time.Hour || l.SessionIdleTimeout.Duration != 30*time.Minute || l.SessionsPerPrincipal != 8 ||
		l.CatalogTTLMs != 60000 || l.CatalogPageSize != 100 || l.ListenStreamsPerSess != 2 {
		t.Fatalf("defaults differ from Appendix A: %+v", l)
	}
	bad := map[string]string{
		"non-loopback":      strings.Replace(good, "[admin]", "[listener]\naddress = \"0.0.0.0:8443\"\n[admin]", 1),
		"http public url":   strings.Replace(good, "[admin]", "[listener]\npublic_url = \"http://x\"\n[admin]", 1),
		"bad alias":         strings.Replace(good, `alias = "fs"`, `alias = "File-Server"`, 1),
		"unknown field":     strings.Replace(good, `username = "admin"`, "username = \"admin\"\nrole = \"x\"", 1),
		"unknown principal": strings.Replace(good, `principal = "cc"`, `principal = "zz"`, 1),
		"plain hash":        strings.Replace(good, "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA", "hunter2", 1),
		"no admin":          strings.Replace(good, "[admin]", "[other]", 1),
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
