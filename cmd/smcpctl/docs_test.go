package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// repoRoot is the repository root relative to this package directory.
const repoRoot = "../.."

// docFiles returns README.md and every Markdown file under docs/.
func docFiles(t *testing.T) []string {
	t.Helper()
	files := []string{filepath.Join(repoRoot, "README.md")}
	err := filepath.WalkDir(filepath.Join(repoRoot, "docs"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".md") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

var (
	fenceRe   = regexp.MustCompile("(?s)```[a-z]*\n(.*?)```")
	spanRe    = regexp.MustCompile("`([^`\n]+)`")
	commandRe = regexp.MustCompile(`\bsmcpctl ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?`)
	usageCmd  = regexp.MustCompile(`(?m)^  ([a-z][a-z-]*)(?: ([a-z][a-z-]*))?\s{2,}`)
	commentRe = regexp.MustCompile(`(?m)(^|\s)#.*$`)
)

// codeText returns the contents of fenced code blocks and inline code spans
// of a Markdown document: the places where a command is written to be run.
func codeText(md string) []string {
	var out []string
	for _, m := range fenceRe.FindAllStringSubmatch(md, -1) {
		out = append(out, commentRe.ReplaceAllString(m[1], ""))
	}
	rest := fenceRe.ReplaceAllString(md, "")
	for _, m := range spanRe.FindAllStringSubmatch(rest, -1) {
		out = append(out, m[1])
	}
	return out
}

// subcommands lists, per command group, the words that may follow it. Groups
// with their own usage text are read from it; the others are listed here
// from the dispatch in main.go and the group's own argument check.
func subcommands() map[string]string {
	return map[string]string{
		"approvals": approvalsUsage,
		"approvers": approversUsage,
		"clients":   clientsUsage,
		"client":    clientsUsage,
		"egress":    egressUsage,
		"graph":     graphUsage,
		"observe":   observeUsage,
		"filters":   filtersUsage,
		"policy":    policyUsage + " reload",
		"remote":    remoteUsage,
		"runtime":   runtimeUsage,
		"secrets":   secretsUsage,
		"servers":   serversUsage,
		"package":   packageUsage,
		"trust":     trustUsage,
		"keys":      "status rotate",
		"config":    "validate migrate",
		"journal":   "verify export",
		"admin":     "redeem",
		"health":    "ack",
		"lockdown":  "apply show remove",
	}
}

// TestDocumentedCommandsExist checks that every smcpctl command written in
// a code span or code block of README.md and docs/ is a command of this
// build: the first word is a command in the top-level usage, and for
// command groups the second word is one of the group's subcommands.
func TestDocumentedCommandsExist(t *testing.T) {
	top := map[string]bool{"help": true, "client": true}
	for _, m := range usageCmd.FindAllStringSubmatch(usage, -1) {
		top[m[1]] = true
	}
	groups := subcommands()
	wordIn := func(word, text string) bool {
		return regexp.MustCompile(`(^|[^a-z-])` + regexp.QuoteMeta(word) + `([^a-z-]|$)`).MatchString(text)
	}
	seen := 0
	for _, f := range docFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range codeText(string(b)) {
			for _, m := range commandRe.FindAllStringSubmatch(code, -1) {
				seen++
				cmd, sub := m[1], m[2]
				if !top[cmd] {
					t.Errorf("%s: `smcpctl %s` is not an smcpctl command", f, cmd)
					continue
				}
				if g, ok := groups[cmd]; ok && sub != "" && !wordIn(sub, g) {
					t.Errorf("%s: `smcpctl %s %s`: %q is not a subcommand of %s", f, cmd, sub, sub, cmd)
				}
			}
		}
	}
	if seen < 100 {
		t.Fatalf("found only %d documented smcpctl commands; the extraction is broken", seen)
	}
}

// section returns the text of the "## heading" section of md, or "".
func section(md, heading string) string {
	i := strings.Index(md, "\n## "+heading+"\n")
	if i < 0 {
		return ""
	}
	body := md[i+len(heading)+5:]
	if j := strings.Index(body, "\n## "); j >= 0 {
		body = body[:j]
	}
	return body
}

// TestOperatorGuideCoversFR18_4 inspects docs/operator-guide.md: one
// section for each FR-18.4 topic, and each section names the smcpctl
// commands or console views that perform it. TestDocumentedCommandsExist
// checks that those commands exist.
func TestOperatorGuideCoversFR18_4(t *testing.T) {
	reqtest.Verifies(t, "FR-18.4")
	b, err := os.ReadFile(filepath.Join(repoRoot, "docs", "operator-guide.md"))
	if err != nil {
		t.Fatal(err)
	}
	md := string(b)
	topics := map[string]string{
		"roles and accounts":                     "Accounts and roles",
		"approvals":                              "Approvals",
		"sessions":                               "Sessions and clients",
		"server enablement/suspension":           "Servers and packages",
		"emergency stop":                         "Emergency stop",
		"backups and restore":                    "Backups and restore",
		"key rotation":                           "Keys and certificates",
		"configuration reload, logs and metrics": "Configuration reload, logs and metrics",
	}
	for topic, heading := range topics {
		body := section(md, heading)
		if body == "" {
			t.Errorf("operator guide has no section %q for the FR-18.4 topic %s", heading, topic)
			continue
		}
		if !strings.Contains(body, "smcpctl ") && !strings.Contains(body, "console") {
			t.Errorf("section %q names neither an smcpctl command nor a console view", heading)
		}
	}
	for _, want := range []string{"smcpctl package disable", "smcpctl stop", "smcpctl resume", "smcpctl restore", "smcpctl keys rotate", "smcpctl reload", "[metrics] enabled", "smcpd.log"} {
		if !strings.Contains(md, want) {
			t.Errorf("operator guide does not mention %q", want)
		}
	}
}

// TestScopeStatementFR18_9 inspects README.md and docs/README.md for the two
// v1 scope statements.
func TestScopeStatementFR18_9(t *testing.T) {
	reqtest.Verifies(t, "FR-18.9")
	for _, f := range []string{"README.md", filepath.Join("docs", "README.md")} {
		b, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatal(err)
		}
		md := strings.Join(strings.Fields(string(b)), " ")
		if !strings.Contains(md, "Remote (hosted) MCP servers cannot be used as backends in v1") {
			t.Errorf("%s does not state that remote MCP servers are not supported as backends in v1", f)
		}
		if !regexp.MustCompile(`relays MCP (\*\*)?tools(\*\*)?( only)?\. Resources and prompts are not supported`).MatchString(md) {
			t.Errorf("%s does not state that the Gateway relays tools only, without resources or prompts", f)
		}
	}
}

// TestDocumentationSetFR18 checks that the FR-18 documents and the FR-18.8
// runbooks exist and are listed in the documentation index. Partial: FR-18.1
// asks for the install guide to be followed on clean hosts, and FR-18.8 for
// a recorded execution of each runbook against the release commit; neither
// is done.
func TestDocumentationSetFR18(t *testing.T) {
	reqtest.Partial(t, "FR-18", "FR-18.1", "FR-18.8")
	index, err := os.ReadFile(filepath.Join(repoRoot, "docs", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		"install.md", "quickstart.md", "operator-guide.md", "security-limitations.md",
		"troubleshooting.md", "policy-reference.md", "packaging-guide.md", "clients/README.md",
		"runbooks/emergency-stop.md", "runbooks/revocation.md", "runbooks/backup-restore.md",
		"runbooks/upgrade-rollback.md", "runbooks/key-rotation.md", "runbooks/key-compromise.md",
		"runbooks/policy-rollback.md",
	} {
		if _, err := os.Stat(filepath.Join(repoRoot, "docs", f)); err != nil {
			t.Errorf("docs/%s: %v", f, err)
		}
		if !strings.Contains(string(index), "("+f+")") {
			t.Errorf("docs/README.md does not link %s", f)
		}
	}
	b, err := os.ReadFile(filepath.Join(repoRoot, "docs", "install.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Upgrade and rollback", "## Uninstall", "cosign verify-blob", "Enforced", "Standalone"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("docs/install.md lacks %q", want)
		}
	}
}

// TestDocLinksResolve checks that every relative Markdown link in README.md
// and docs/ points to an existing file.
func TestDocLinksResolve(t *testing.T) {
	linkRe := regexp.MustCompile(`\]\(([^)#\s]+)(#[^)\s]*)?\)`)
	for _, f := range docFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := fenceRe.ReplaceAllString(string(b), "")
		for _, m := range linkRe.FindAllStringSubmatch(text, -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(f), target)); err != nil {
				t.Errorf("%s: link %q does not resolve", f, target)
			}
		}
	}
}
