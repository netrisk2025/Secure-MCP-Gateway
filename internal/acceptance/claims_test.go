package acceptance

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// atLiteral matches a scenario ID at the start of a Go string literal
// ("AT-01") or of a TypeScript template literal (`AT-07 profile=...`, the
// scenario annotation of console/e2e/inert.spec.ts).
var atLiteral = regexp.MustCompile("(?:\"(AT-(?:0[1-9]|1[0-9]|2[01]))\"|`(AT-(?:0[1-9]|1[0-9]|2[01])) profile=)")

// scenarioEvidence returns, per scenario ID, the files that claim it: Go
// test files that call reqtest.Scenario (directly or through the
// acceptance harness) and name the ID, console Playwright specs with a
// "scenario" annotation, and recorded executions docs/verification/AT-nn.md.
func scenarioEvidence(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	add := func(id, file string) {
		rel, _ := filepath.Rel(repoRoot, file)
		for _, f := range out[id] {
			if f == rel {
				return
			}
		}
		out[id] = append(out[id], rel)
	}
	err := filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "build", "archive", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		isGo := strings.HasSuffix(p, "_test.go")
		isSpec := strings.HasSuffix(p, ".spec.ts") && strings.Contains(filepath.ToSlash(p), "console/e2e/")
		if !isGo && !isSpec {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		if isGo && !strings.Contains(s, "reqtest.Scenario(") && !strings.Contains(s, ".scenario(") {
			return nil
		}
		if isSpec && !strings.Contains(s, `type: "scenario"`) {
			return nil
		}
		if filepath.Base(p) == "claims_test.go" {
			return nil
		}
		for _, m := range atLiteral.FindAllStringSubmatch(s, -1) {
			add(m[1]+m[2], p) // one of the two groups is empty
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := filepath.Glob(filepath.Join(repoRoot, "docs", "verification", "AT-*.md"))
	for _, r := range recs {
		id := strings.TrimSuffix(filepath.Base(r), ".md")
		add(id, r)
	}
	return out
}

// TestEveryScenarioHasEvidence is FR-19.4: every acceptance scenario of
// Appendix M has automated tests that claim it by its ID, or a recorded
// execution file. It lists the evidence of each scenario and the scenarios
// without any; the claim is full only when none is missing. Whether the
// claiming tests pass is in the requirement report's acceptance section
// (tools/reqreport), not here.
func TestEveryScenarioHasEvidence(t *testing.T) {
	ev := scenarioEvidence(t)
	var missing []string
	for i := 1; i <= 21; i++ {
		id := fmt.Sprintf("AT-%02d", i)
		files := ev[id]
		sort.Strings(files)
		if len(files) == 0 {
			missing = append(missing, id)
			continue
		}
		t.Logf("%s: %s", id, strings.Join(files, ", "))
	}
	if len(missing) == 0 {
		reqtest.Verifies(t, "FR-19.4")
		return
	}
	reqtest.Partial(t, "FR-19.4")
	t.Logf("scenarios without claiming tests or records: %s", strings.Join(missing, ", "))
}
