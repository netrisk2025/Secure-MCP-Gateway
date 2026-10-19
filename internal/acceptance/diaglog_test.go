package acceptance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestDiagnosticLogLevelsAndContent runs the real smcpd with a session at
// each diagnostic level.
//
// FR-17.1: the diagnostic log is <state>/log/smcpd.log, outside the
// journal directory; every line is a JSON object with a level; at each
// configured level no line of a lower level appears, and with no level set
// the default is info (info lines, no debug lines); debug shows the debug
// trace; no diagnostic message appears in the Evidence Journal.
//
// FR-17.3 in part: at every level, including debug, the log holds none of
// the access token, the approver and administrator passwords, the tool
// argument marker or the tool result. Registered secret values and refresh
// tokens are checked at debug level in TestDiagnosticLogExcludesSecrets.
func TestDiagnosticLogLevelsAndContent(t *testing.T) {
	reqtest.Verifies(t, "FR-17.1")
	reqtest.Partial(t, "FR-17.3")
	g := newGateway(t, options{})
	logFile := filepath.Join(g.state, "log", "smcpd.log")
	rank := map[string]int{"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}
	journalDir := filepath.Join(g.state, "journal")
	if rel, err := filepath.Rel(journalDir, logFile); err == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("diagnostic log %s is inside the journal directory", logFile)
	}

	for i, level := range []string{"", "error", "warn", "info", "debug"} {
		if i == 1 {
			g.appendConfig("\n[log]\nlevel = \"error\"\n")
		} else if i > 1 {
			raw, _ := os.ReadFile(g.cfg)
			prev := []string{"", "error", "warn", "info", "debug"}[i-1]
			s := strings.Replace(string(raw), "\n[log]\nlevel = \""+prev+"\"\n", "\n[log]\nlevel = \""+level+"\"\n", 1)
			if s == string(raw) {
				t.Fatal("could not set the log level")
			}
			writeFile(t, g.dir, "smcp.toml", s, 0o600)
		}
		_ = os.Remove(logFile)
		g.start()
		marker := "diag-marker-" + strings.Repeat("q", 8) + level
		tok := g.freshToken()
		cs := g.session(tok)
		result := g.mustCall(cs, "ref_echo", map[string]any{"text": marker}, marker)
		cs.Close()
		g.stop()

		raw, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("level %q: no diagnostic log: %v", level, err)
		}
		want := level
		if want == "" {
			want = "info"
		}
		minRank := rank[strings.ToUpper(want)]
		seen := map[string]bool{}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var line map[string]any
			if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
				t.Fatalf("level %q: not JSON Lines: %q", level, sc.Text())
			}
			lv, _ := line["level"].(string)
			r, ok := rank[lv]
			if !ok {
				t.Fatalf("level %q: unknown level %q", level, lv)
			}
			if r < minRank {
				t.Fatalf("level %q: a %s line passed the filter: %s", level, lv, sc.Text())
			}
			seen[lv] = true
		}
		switch want {
		case "info":
			if !seen["INFO"] || seen["DEBUG"] {
				t.Fatalf("level %q: levels seen %v", level, seen)
			}
		case "debug":
			if !seen["DEBUG"] || !strings.Contains(string(raw), `"msg":"call event"`) {
				t.Fatalf("debug: no debug trace: %v", seen)
			}
		}
		for what, v := range map[string]string{"access token": tok, "approver password": approverPassword, "administrator password": adminPassword,
			"argument marker": marker, "tool result": result} {
			if strings.Contains(string(raw), v) {
				t.Fatalf("level %q: the diagnostic log holds the %s", level, what)
			}
		}
	}
	// No diagnostic entry in the journal.
	journal := g.journalText()
	for _, msg := range []string{"smcpd listening", "call event", "server enabled"} {
		if strings.Contains(journal, msg) {
			t.Fatalf("diagnostic message %q in the journal", msg)
		}
	}
}
