package config

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEgressDefaults(t *testing.T) {
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	e := cfg.Egress
	if e.Enabled || !*e.ProxyEnv || e.RequestBytes != 1<<20 || e.ResponseBytes != 8<<20 || e.OperationTimeout.Duration != 30*time.Second ||
		e.DialTimeout.Duration != 10*time.Second || e.RequestsPerMinute != 60 || e.BytesPerMinute != 64<<20 || e.RecentRecords != 256 ||
		!*e.RequireCapability || e.CapabilityTokens != 8 || len(e.Resolvers) != 0 || e.CAFile != "" {
		t.Fatalf("%+v", e)
	}
	cfg, err = Parse([]byte(good + `
[egress]
enabled = true
recent_records = 0
[[egress.grant]]
server = "fs"
host = "API.Example.com."
methods = ["GET"]
`))
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.Egress.Grants[0]
	if cfg.Egress.RecentRecords != 0 || g.Host != "api.example.com" || g.Class != EgressClassAPI || !slices.Equal(g.Ports, []int{443}) || g.Methods[0] != "GET" {
		t.Fatalf("%+v %+v", cfg.Egress, g)
	}
}

func TestEgressSchemaMatchesDefaults(t *testing.T) {
	var s struct {
		Properties map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(SchemaJSON(), &s); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range s.Properties["egress"].Properties {
		// Keys without a numeric default: booleans defaulted in
		// applyDefaults, the grant list and the optional resolver and CA.
		if !slices.Contains([]string{"enabled", "proxy_env", "require_capability", "grant", "resolvers", "ca_file"}, k) {
			keys = append(keys, k)
		}
	}
	var defs []string
	for _, d := range EgressDefaults {
		defs = append(defs, d.Key)
	}
	slices.Sort(keys)
	slices.Sort(defs)
	if !slices.Equal(keys, defs) {
		t.Fatalf("schema %v defaults %v", keys, defs)
	}
}

func TestEgressGrantValidation(t *testing.T) {
	for name, tc := range map[string]struct{ grant, want string }{
		"unknown server":           {`server = "zz"` + "\n" + `host = "a.com"` + "\nmethods = [\"GET\"]", "unknown server alias"},
		"bad address":              {`server = "fs"` + "\n" + `host = "a.com"` + "\nmethods = [\"GET\"]\naddresses = [\"10.0.0.300\"]", "not an IP address"},
		"public-fetch no endpoint": {`server = "fs"` + "\n" + `host = "a.com"` + "\nmethods = [\"GET\"]\nclass = \"public-fetch\"", "endpoint_env"},
		"public-fetch POST":        {`server = "fs"` + "\n" + `host = "a.com"` + "\nmethods = [\"GET\", \"POST\"]\nclass = \"public-fetch\"\nendpoint_env = \"A\"", "only GET"},
		"wildcard endpoint":        {`server = "fs"` + "\n" + `host = "*.a.com"` + "\nmethods = [\"GET\"]\nendpoint_env = \"A\"", "exact host"},
		"two ports endpoint":       {`server = "fs"` + "\n" + `host = "a.com"` + "\nports = [443, 8443]\nmethods = [\"GET\"]\nendpoint_env = \"A\"", "exactly one port"},
		"unknown method":           {`server = "fs"` + "\n" + `host = "a.com"` + "\nmethods = [\"TRACE\"]", "schema"},
		"bad host":                 {`server = "fs"` + "\n" + `host = "a b.com"` + "\nmethods = [\"GET\"]", "schema"},
	} {
		_, err := Parse([]byte(good + "\n[egress]\n[[egress.grant]]\n" + tc.grant + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	dup := good + "\n[egress]\n[[egress.grant]]\nserver = \"fs\"\nhost = \"a.com\"\nmethods = [\"GET\"]\nendpoint_env = \"A\"\n" +
		"[[egress.grant]]\nserver = \"fs\"\nhost = \"b.com\"\nmethods = [\"GET\"]\nendpoint_env = \"A\"\n"
	if _, err := Parse([]byte(dup)); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("duplicate endpoint_env: %v", err)
	}
	if _, err := Parse([]byte(good + "\n[egress]\noperation_timeout = \"0s\"\n")); err == nil {
		t.Error("zero operation_timeout accepted")
	}
	if _, err := Parse([]byte(good + "\n[egress]\nresolvers = [\"dns.example:53\"]\n")); err == nil || !strings.Contains(err.Error(), "IP address and port") {
		t.Errorf("resolver by name: %v", err)
	}
	if _, err := Parse([]byte(good + "\n[egress]\ncapability_tokens = 0\n")); err == nil {
		t.Error("capability_tokens = 0 accepted")
	}
	cfg, err := Parse([]byte(good + "\n[egress]\nrequire_capability = false\ncapability_tokens = 2\nresolvers = [\"127.0.0.1:5353\", \"[::1]:53\"]\nca_file = \"ca.pem\"\n"))
	if err != nil || *cfg.Egress.RequireCapability || cfg.Egress.CapabilityTokens != 2 || len(cfg.Egress.Resolvers) != 2 || cfg.Egress.CAFile != "ca.pem" {
		t.Errorf("%v %+v", err, cfg)
	}
}
