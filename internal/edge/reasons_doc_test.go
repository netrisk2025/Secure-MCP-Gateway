package edge

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// reasonLiteral finds reason codes in Go source: constants and fields named
// Reason..., ReasonCode struct fields and the reason argument of
// gatewayError.
var reasonLiteral = regexp.MustCompile(`(?:\bReason[A-Za-z0-9]*\s*=\s*|ReasonCode:\s*|gatewayError\([^,]+,\s*"[^"]*",\s*)"([A-Z][A-Z0-9_]{2,})"`)

// reasonFamilies are reason codes built from a prefix and a state at run
// time; the scan finds the prefix, and every expansion must be documented.
// A new prefix fails the check until its expansions are listed here.
var reasonFamilies = map[string][]string{
	"ANOMALY_":  {"ANOMALY_ELEVATED", "ANOMALY_ABNORMAL", "ANOMALY_CRITICAL"},            // internal/analytics: bands from elevated up
	"BASELINE_": {"BASELINE_PROMOTED", "BASELINE_AUTO_PROMOTED", "BASELINE_ROLLED_BACK"}, // internal/baseline promotion modes
	"DCR_":      {"DCR_APPROVED", "DCR_DENIED", "DCR_REVOKED"},                           // internal/remote registration decisions
	"DEVICE_":   {"DEVICE_APPROVED", "DEVICE_DENIED"},                                    // internal/remote device decisions
	"HEALTH_":   {"HEALTH_HEALTHY", "HEALTH_DEGRADED", "HEALTH_FAIL_CLOSED"},             // internal/health states
}

// TestReasonCodesDocumented is the build check of FR-18.7: every reason
// code the Gateway's source emits, and every Appendix B error code, is
// explained in docs/troubleshooting.md in a table row whose last cell (the
// operator's next action) is filled in. A new reason code without an entry
// fails the build.
func TestReasonCodesDocumented(t *testing.T) {
	reqtest.Verifies(t, "FR-18.7")
	root := filepath.Join("..", "..")
	guide, err := os.ReadFile(filepath.Join(root, "docs", "troubleshooting.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Each documented code maps to the next-action cell of its row.
	action := map[string]string{}
	codeRef := regexp.MustCompile("`([A-Za-z0-9_-]+)`")
	for _, line := range strings.Split(string(guide), "\n") {
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 4 {
			continue
		}
		last := strings.TrimSpace(cells[len(cells)-1])
		for _, cell := range cells[:2] {
			for _, m := range codeRef.FindAllStringSubmatch(cell, -1) {
				if _, seen := action[m[1]]; !seen {
					action[m[1]] = last
				}
			}
		}
	}

	found := map[string]string{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			for _, m := range reasonLiteral.FindAllStringSubmatch(string(src), -1) {
				codes := []string{m[1]}
				if strings.HasSuffix(m[1], "_") {
					exp, ok := reasonFamilies[m[1]]
					if !ok {
						t.Errorf("%s builds reason codes from the prefix %q; list its expansions in reasonFamilies", rel, m[1])
						continue
					}
					codes = exp
				}
				for _, c := range codes {
					if _, ok := found[c]; !ok {
						found[c] = rel
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) < 100 {
		t.Fatalf("found only %d reason codes; the scan is broken", len(found))
	}
	for _, code := range []string{"-31001", "-31002", "-31003", "-31004", "-31005", "-31006", "-31007", "-31008", "-31009", "-31010"} {
		found[code] = "SRS Appendix B"
	}
	var missing []string
	for code, file := range found {
		next, ok := action[code]
		switch {
		case !ok && strings.HasPrefix(code, "-"):
			// An error code is explained by the rows that carry it.
			if !strings.Contains(string(guide), "`"+code+"`") {
				missing = append(missing, code+" ("+file+")")
			}
		case !ok:
			missing = append(missing, code+" ("+file+")")
		case next == "":
			missing = append(missing, code+" ("+file+"): no next action")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d reason or error codes are not explained in docs/troubleshooting.md:\n%s", len(missing), strings.Join(missing, "\n"))
	}
}
