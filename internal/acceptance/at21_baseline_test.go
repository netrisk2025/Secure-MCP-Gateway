package acceptance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

const repoRoot = "../.."

// srsRequirementIDs counts the requirements of srs_build/req*.txt the way
// the SRS defines the set: every "@ID | title" record without a DEFER: line,
// excluding "@DISP" dispositions.
func srsRequirementIDs(t *testing.T) map[string]bool {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(repoRoot, "srs_build", "req*.txt"))
	ids := map[string]bool{}
	for _, fn := range files {
		f, err := os.Open(fn)
		if err != nil {
			t.Fatal(err)
		}
		cur, deferred := "", false
		flush := func() {
			if cur != "" && !deferred {
				ids[cur] = true
			}
			cur, deferred = "", false
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<16), 1<<22)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "@DISP "):
				flush()
			case strings.HasPrefix(line, "@"):
				flush()
				cur, _, _ = strings.Cut(line[1:], " | ")
			case strings.HasPrefix(line, "DEFER:"):
				deferred = true
			}
		}
		flush()
		f.Close()
	}
	return ids
}

// TestAT21VersionBaseline is acceptance scenario AT-21:
//
//   - the committed SRS regenerates from srs_build without change;
//   - the requirement report lists exactly the requirements of the SRS
//     (counted here independently from srs_build), every requirement
//     without a claim as unverified, and the Appendix M scenarios with the
//     release label, which is "not enforced" without results (FR-19.3);
//   - the documents the SRS names as its baseline (architecture version,
//     security SRS, MCP schema revision) resolve in the same tree, so the
//     release tag of this commit resolves the matching documents;
//   - the running Gateway reports its release label.
//
// Partial: FR-12.10's comparison with the published status data and
// FR-19.3's inspection of an actual release record happen in CI and at
// release (tools/reqreport label in release.yml).
func TestAT21VersionBaseline(t *testing.T) {
	g := newGateway(t, options{})
	g.start()
	g.scenario("AT-21")
	reqtest.Partial(t, "FR-12.10", "FR-19.3")

	// The SRS regenerates without change.
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is needed to regenerate the SRS")
	}
	out := filepath.Join(t.TempDir(), "srs.md")
	if b, err := exec.Command(python, "-I", filepath.Join(repoRoot, "srs_build", "gen.py"), repoRoot, out).CombinedOutput(); err != nil {
		t.Fatalf("gen.py: %v %s", err, b)
	}
	regen, _ := os.ReadFile(out)
	committed, err := os.ReadFile(filepath.Join(repoRoot, "Secure_MCP_Gateway_SRS.md"))
	if err != nil || !bytes.Equal(regen, committed) {
		t.Fatalf("the committed SRS differs from srs_build (%v)", err)
	}

	// The requirement report is complete.
	work := t.TempDir()
	empty := writeFile(t, work, "empty.json", "", 0o644)
	cmd := exec.Command("go", "run", "./tools/reqreport", "-in", empty, "-out", filepath.Join(work, "rr"), "-status", filepath.Join(work, "status.json"),
		"-agents", "", "-hostile", "", "-commit", strings.Repeat("a", 40))
	cmd.Dir = repoRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reqreport: %v %s", err, b)
	}
	var st struct {
		Requirements struct {
			Total, Verified, Partial, Failing, Unverified int
			Items                                         []struct {
				ID, Status string
				Tests      []string
			}
		}
		Acceptance struct {
			Label     string
			Total     int
			Scenarios []struct{ ID string }
		}
	}
	raw, _ := os.ReadFile(filepath.Join(work, "status.json"))
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	want := srsRequirementIDs(t)
	if st.Requirements.Total != len(want) || len(st.Requirements.Items) != len(want) {
		t.Fatalf("report lists %d requirements, the SRS has %d", st.Requirements.Total, len(want))
	}
	for _, it := range st.Requirements.Items {
		if !want[it.ID] {
			t.Fatalf("report lists %s, which is not an SRS requirement", it.ID)
		}
		// Records and child analysis can verify without tests, and child
		// analysis makes a parent partial when some children have evidence.
		rollup := it.Status == "partial" && len(it.Tests) == 1 && strings.HasPrefix(it.Tests[0], "analysis: ")
		if it.Status != "unverified" && it.Status != "verified" && !rollup {
			t.Fatalf("%s is %s without any test claim (%v)", it.ID, it.Status, it.Tests)
		}
	}
	if st.Acceptance.Total != 21 || len(st.Acceptance.Scenarios) != 21 || st.Acceptance.Label != "not enforced" {
		t.Fatalf("acceptance section: %+v", st.Acceptance)
	}

	// The baseline documents resolve in this tree.
	srs := string(committed)
	arch := regexp.MustCompile("\\| Architecture \\| `([^`]+)` (V[0-9.]+)").FindStringSubmatch(srs)
	sec := regexp.MustCompile("\\| Security control root \\| `([^`]+)`").FindStringSubmatch(srs)
	proto := regexp.MustCompile("\\| Protocol baseline \\| .*\\(`([^`]+)`").FindStringSubmatch(srs)
	if arch == nil || sec == nil || proto == nil {
		t.Fatal("the SRS header does not name its baseline documents")
	}
	archDoc, err := os.ReadFile(filepath.Join(repoRoot, arch[1]))
	if err != nil || !strings.Contains(string(archDoc[:min(len(archDoc), 4096)]), arch[2]) {
		t.Fatalf("%s does not carry version %s (%v)", arch[1], arch[2], err)
	}
	for _, p := range []string{sec[1], proto[1]} {
		if _, err := os.Stat(filepath.Join(repoRoot, strings.TrimSuffix(p, "/"))); err != nil {
			t.Fatalf("baseline document %s: %v", p, err)
		}
	}

	// The running Gateway reports its release label.
	ver := g.mustCtl("version")
	label := "not enforced"
	if g.profile() == reqtest.Enforced {
		label = "" // either label is possible; the label must be present
	}
	if !strings.Contains(ver, "enforced") || !strings.Contains(ver, label) {
		t.Fatalf("smcpctl version: %s", ver)
	}
	g.stop()
}
