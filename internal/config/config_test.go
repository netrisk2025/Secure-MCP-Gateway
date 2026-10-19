package config

import (
	"encoding/json"
	"fmt"
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
command = "/usr/local/bin/refserver"
`

const goodHash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA"

// withBefore inserts TOML before the first principal table.
func withBefore(extra string) string {
	return strings.Replace(good, "[[principal]]", extra+"[[principal]]", 1)
}

func TestDefaultsAndSchema(t *testing.T) {
	reqtest.Verifies(t, "FR-12.6")
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listener.Address != "127.0.0.1:8443" || cfg.ResourceURI() != "https://127.0.0.1:8443/mcp" {
		t.Fatalf("%+v", cfg.Listener)
	}
	if cfg.AdminListener.Address != "127.0.0.1:8444" || cfg.Profile.Mode != "auto" || cfg.Log.Level != "info" {
		t.Fatalf("%+v %+v %+v", cfg.AdminListener, cfg.Profile, cfg.Log)
	}
	l := cfg.Limits
	if l.RequestBodyBytes != 1<<20 || l.ResultBytes != 8<<20 || l.ToolConcurrencyPerUser != 4 || l.ToolConcurrencyTotal != 16 || l.ToolQueue != 32 ||
		l.PrincipalCallsPerMin != 60 || l.UpstreamTimeout.Duration != 45*time.Second || l.ClientDeadline.Duration != 60*time.Second ||
		l.SessionMaxLifetime.Duration != 8*time.Hour || l.SessionIdleTimeout.Duration != 30*time.Minute || l.SessionsPerPrincipal != 8 ||
		l.CatalogTTLMs != 60000 || l.CatalogPageSize != 100 || l.ListenStreamsPerSess != 2 || l.ApprovalHold.Duration != 120*time.Second {
		t.Fatalf("defaults differ from Appendix A: %+v", l)
	}
	bad := map[string]string{
		"non-loopback":      strings.Replace(good, "[admin]", "[listener]\naddress = \"0.0.0.0:8443\"\n[admin]", 1),
		"http public url":   strings.Replace(good, "[admin]", "[listener]\npublic_url = \"http://x\"\n[admin]", 1),
		"bad alias":         strings.Replace(good, `alias = "fs"`, `alias = "File-Server"`, 1),
		"unknown field":     strings.Replace(good, `username = "admin"`, "username = \"admin\"\nrole = \"x\"", 1),
		"unknown principal": strings.Replace(good, `principal = "cc"`, `principal = "zz"`, 1),
		"plain hash":        strings.Replace(good, goodHash, "hunter2", 1),
		"no admin":          strings.Replace(good, "[admin]", "[other]", 1),
		"bad profile":       withBefore("[profile]\nmode = \"loose\"\n"),
		"bad risk class":    strings.Replace(good, `alias = "fs"`, "alias = \"fs\"\nrisk_classes = [\"spicy\"]", 1),
		"secret env twice":  strings.Replace(good, `alias = "fs"`, "alias = \"fs\"\nenv = { TOKEN = \"x\" }\nsecret_env = { TOKEN = \"vault:t\" }", 1),
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExplicitZeroLimitsHonored(t *testing.T) {
	reqtest.Verifies(t, "FR-12.6")
	cfg, err := Parse([]byte(withBefore("[limits]\ntool_queue = 0\ncatalog_ttl_ms = 0\n")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.ToolQueue != 0 || cfg.Limits.CatalogTTLMs != 0 {
		t.Fatalf("explicit zero replaced by default: queue=%d ttl=%d", cfg.Limits.ToolQueue, cfg.Limits.CatalogTTLMs)
	}
	if cfg.Limits.ToolConcurrencyTotal != 16 {
		t.Fatal("absent key not defaulted")
	}
	for name, extra := range map[string]string{
		"zero duration":     "[limits]\nupstream_timeout = \"0s\"\n",
		"garbage duration":  "[limits]\nclient_deadline = \"soon\"\n",
		"negative queue":    "[limits]\ntool_queue = -1\n",
		"same admin port":   "[admin_listener]\naddress = \"127.0.0.1:8443\"\n",
		"approver is admin": "[[approver]]\nusername = \"admin\"\npassword_hash = \"" + goodHash + "\"\n",
	} {
		if _, err := Parse([]byte(withBefore(extra))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSchemaAndDefaultsAgree(t *testing.T) {
	reqtest.Verifies(t, "FR-12.6")
	var schema struct {
		Properties struct {
			Limits struct {
				Properties map[string]any `json:"properties"`
			} `json:"limits"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(SchemaJSON(), &schema); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, d := range LimitDefaults {
		keys[d.Key] = true
		if _, ok := schema.Properties.Limits.Properties[d.Key]; !ok {
			t.Errorf("default for %s has no schema property", d.Key)
		}
	}
	for k := range schema.Properties.Limits.Properties {
		if !keys[k] {
			t.Errorf("schema property %s has no default", k)
		}
	}
	// Every default, written out explicitly, must pass the schema and checks.
	var b strings.Builder
	b.WriteString("[limits]\n")
	for _, d := range LimitDefaults {
		switch v := d.Value.(type) {
		case time.Duration:
			fmt.Fprintf(&b, "%s = %q\n", d.Key, v.String())
		default:
			fmt.Fprintf(&b, "%s = %v\n", d.Key, v)
		}
	}
	explicit, err := Parse([]byte(withBefore(b.String())))
	if err != nil {
		t.Fatalf("defaults do not pass the schema: %v", err)
	}
	implicit, _ := Parse([]byte(good))
	if explicit.Limits != implicit.Limits {
		t.Fatalf("explicit defaults %+v differ from implicit %+v", explicit.Limits, implicit.Limits)
	}
}

func TestBootstrapTokenAdminApproversAndRiskClasses(t *testing.T) {
	reqtest.Verifies(t, "FR-12.6")
	src := strings.Replace(good, `password_hash = "`+goodHash+`"`,
		"bootstrap_token_sha256 = \""+strings.Repeat("a", 64)+"\"\nbootstrap_token_expires = \"2026-10-17T00:00:00Z\"", 1)
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.PasswordHash != "" || cfg.Admin.BootstrapTokenSHA256 == "" {
		t.Fatalf("%+v", cfg.Admin)
	}
	if _, err := Parse([]byte(strings.Replace(good, `password_hash = "`+goodHash+`"`, "", 1))); err == nil {
		t.Fatal("admin without any credential accepted")
	}
	cfg, err = Parse([]byte(withBefore("[[approver]]\nusername = \"ethan\"\npassword_hash = \"" + goodHash + "\"\n")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FindApprover("ethan") == nil || cfg.FindApprover("admin") != nil {
		t.Fatal("approver lookup")
	}
	cfg, err = Parse([]byte(strings.Replace(good, `alias = "fs"`, "alias = \"fs\"\nrisk_classes = [\"code-execution\"]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Servers[0].HighRisk() {
		t.Fatal("code-execution not high risk")
	}
}
