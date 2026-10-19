package config

import (
	"testing"
	"time"
)

const filtersBase = `
[admin]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
`

func TestFiltersSection(t *testing.T) {
	cfg, err := Parse([]byte(filtersBase + `
[filters]
rules_dir = "rules"
rule_versions = { prompt-injection = "2026.10.1" }
deadline = "500ms"
mandatory_request = ["size-limit", "secret-fingerprint"]
mandatory_response = ["size-limit"]
metadata_scan = false
[filters.size]
argument_bytes = 4096
argument_depth = 8
[filters.paths]
roots = ["/srv/data"]
server_roots = { fs = ["/srv/fs"] }
ignore_names = ["route"]
rewrite = false
[filters.urls]
schemes = ["https"]
hosts = ["*.example.org"]
deny_hosts = ["evil.example"]
allow_private = true
[filters.content_types]
allow = ["image/png"]
max_bytes = 65536
`))
	if err != nil {
		t.Fatal(err)
	}
	f := cfg.Filters
	if f.RulesDir != "rules" || f.RuleVersions["prompt-injection"] != "2026.10.1" || f.Deadline.Duration != 500*time.Millisecond ||
		len(f.MandatoryRequest) != 2 || f.MetadataScan == nil || *f.MetadataScan || f.Size.ArgumentBytes != 4096 ||
		f.Paths.ServerRoots["fs"][0] != "/srv/fs" || f.Paths.Rewrite == nil || *f.Paths.Rewrite || !f.URLs.AllowPrivate ||
		f.ContentTypes.Allow[0] != "image/png" {
		t.Fatalf("%+v", f)
	}
	for _, bad := range []string{
		"[filters]\nunknown = 1\n",
		"[filters]\nmandatory_request = [\"Bad ID\"]\n",
		"[filters.size]\nargument_bytes = 0\n",
		"[filters.content_types]\nallow = [\"not a mime\"]\n",
		"[filters]\ndeadline = \"soon\"\n",
	} {
		if _, err := Parse([]byte(filtersBase + bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
