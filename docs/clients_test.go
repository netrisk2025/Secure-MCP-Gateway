package docs

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestCloudAgentEntries guards the records that the FR-15.9 and FR-16.10
// Inspection records rely on: every cloud agent in the client matrix is
// either a dated run with each run field or a not-run entry with its
// review date and reason, and the cloud-agent quick start has, for each
// agent, a vendor allowlist line with a date checked and the sources
// reviewed.
func TestCloudAgentEntries(t *testing.T) {
	raw, err := os.ReadFile("clients/matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Clients []struct {
			Client           string  `json:"client"`
			RunsOn           string  `json:"runsOn"`
			ConnectionMode   *string `json:"connectionMode"`
			RegistrationMode *string `json:"registrationMode"`
			LastResult       string  `json:"lastResult"`
			LastRun          *string `json:"lastRun"`
			TunnelProvider   *string `json:"tunnelProvider"`
			AgentBuild       *string `json:"agentBuild"`
			Reviewed         string  `json:"reviewed"`
			NotRunReason     string  `json:"notRunReason"`
			QuickStart       string  `json:"quickStart"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	set := func(p *string) bool { return p != nil && *p != "" }
	date := func(s string) bool { _, err := time.Parse("2006-01-02", s); return err == nil }
	cloud := 0
	for _, c := range m.Clients {
		if c.RunsOn != "vendor-cloud" {
			continue
		}
		cloud++
		if !set(c.ConnectionMode) || !set(c.RegistrationMode) {
			t.Errorf("%s: connection or registration mode missing", c.Client)
		}
		switch c.LastResult {
		case "pass", "fail":
			if !set(c.LastRun) || !date(*c.LastRun) || !set(c.TunnelProvider) {
				t.Errorf("%s: a run result needs its date and tunnel provider", c.Client)
			}
		case "not-run":
			if !date(c.Reviewed) || strings.TrimSpace(c.NotRunReason) == "" {
				t.Errorf("%s: a not-run entry needs reviewed and notRunReason", c.Client)
			}
		default:
			t.Errorf("%s: result %q", c.Client, c.LastResult)
		}
		qs, err := os.ReadFile(strings.TrimPrefix(c.QuickStart, "docs/"))
		if err != nil {
			t.Errorf("%s: quick start: %v", c.Client, err)
			continue
		}
		name := strings.Split(c.Client, " (")[0]
		name = strings.Split(name, " agent")[0]
		sec := section(string(qs), name)
		if sec == "" {
			t.Errorf("%s: no section in %s", c.Client, c.QuickStart)
			continue
		}
		line := regexp.MustCompile(`(?m)^- Vendor allowlist \(FR-16\.10\): .*$`).FindString(sec)
		if line == "" || !regexp.MustCompile(`checked \d{4}-\d{2}-\d{2}`).MatchString(line) || !strings.Contains(line, "Sources reviewed:") {
			t.Errorf("%s: vendor allowlist line without date checked and sources: %q", c.Client, line)
		}
	}
	if cloud != 3 {
		t.Errorf("%d cloud agents in the matrix, Appendix K lists 3", cloud)
	}
}

// section returns the "## " section of md whose heading contains name.
func section(md, name string) string {
	parts := strings.Split(md, "\n## ")
	for _, p := range parts[1:] {
		head, _, _ := strings.Cut(p, "\n")
		if strings.Contains(head, name) {
			return p
		}
	}
	return ""
}
