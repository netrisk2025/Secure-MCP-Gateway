package acceptance

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// outboundBlocked reports whether this process can reach no Internet
// address: TCP to public resolvers and DNS resolution both fail.
func outboundBlocked() (bool, string) {
	for _, a := range []string{"1.1.1.1:443", "8.8.8.8:53", "[2606:4700:4700::1111]:443"} {
		if c, err := net.DialTimeout("tcp", a, 3*time.Second); err == nil {
			c.Close()
			return false, "connected to " + a
		}
	}
	if addrs, err := net.LookupHost("example.com"); err == nil && len(addrs) > 0 {
		return false, "resolved example.com"
	}
	return true, ""
}

const at17Policy = `{
  "revision": "at17-r2",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [
      {"id": "ref", "server": "ref", "tools": ["echo", "list_files", "read_file", "time_now"]},
      {"id": "fs", "server": "fs", "tools": ["list_directory"]},
      {"id": "git", "server": "git", "tools": ["git_status"]}
    ]},
    "approval-demo": {"rules": [
      {"id": "demo-free", "server": "ref", "tools": ["echo"]},
      {"id": "demo-approve", "server": "ref", "tools": ["read_file"], "approval": true}
    ]}
  }
}`

// TestAT17OfflineEngineeringWorkflow is acceptance scenario AT-17. It runs
// in the CI job "offline", which builds the reference filesystem and git
// packages (scripts/build-reference-packages.sh, the only step that needs
// the registries), then runs the acceptance suite in a network namespace
// with loopback only. The test first proves that no Internet address is
// reachable, then installs the two signed packages offline, enables them,
// calls one tool of each through the Gateway, and exercises the other
// baseline functions: OAuth sign-in, the bundled reference server, an
// approval, policy publication, the console page, a backup and journal
// verification.
//
// The offline job runs it twice: in the Standalone profile, and with
// SMCP_ACCEPTANCE_PROFILE=enforced, where every server runs in rootless
// Podman (the two packages on pinned node and python images).
//
// Elsewhere it skips: SMCP_ACCEPTANCE_OFFLINE=1 marks the offline run and
// SMCP_REFPKG_DIR names the directory with pkg-filesystem, pkg-git and
// reference-test.pub. Partial: FR-12.2 needs every baseline function, and
// AT-07, AT-08 and AT-10 do not run in this job; FR-14.9 covers two of the
// four reference packages offline (the reference-packages job builds and
// calls all four online).
func TestAT17OfflineEngineeringWorkflow(t *testing.T) {
	needBinaries(t)
	if os.Getenv("SMCP_ACCEPTANCE_OFFLINE") != "1" {
		t.Skip("runs in the offline CI job (SMCP_ACCEPTANCE_OFFLINE=1, SMCP_REFPKG_DIR)")
	}
	if ok, why := outboundBlocked(); !ok {
		t.Fatalf("SMCP_ACCEPTANCE_OFFLINE=1 but outbound access is not blocked: %s", why)
	}
	refpkg := os.Getenv("SMCP_REFPKG_DIR")
	node, python := os.Getenv("SMCP_NODE"), os.Getenv("SMCP_PYTHON")
	for _, p := range []string{filepath.Join(refpkg, "pkg-filesystem"), filepath.Join(refpkg, "pkg-git"), filepath.Join(refpkg, "reference-test.pub"), node, python} {
		if _, err := os.Stat(p); err != nil || p == "" {
			t.Fatalf("offline run prerequisite %q: %v", p, err)
		}
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	files, repo := filepath.Join(data, "files"), filepath.Join(data, "repo")
	writeFile(t, files, "hello.txt", "offline filesystem package\n", 0o644)
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "init"}} {
		if out, err := exec.Command(gitBin, append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}

	extra := fmt.Sprintf(`
[[server]]
alias = "fs"
package = "mcp-filesystem"
slots = { root = %q }

[[server]]
alias = "git"
package = "mcp-git"
slots = { repo = %q }

[packages]
node = %q
python = %q
`, files, repo, node, python)
	if requestedProfile() == reqtest.Enforced {
		// In the Enforced profile the node and python packages run in the
		// sandbox on the interpreter of a digest-pinned image, pulled before
		// the run (SMCP_AT17_NODE_IMAGE, SMCP_AT17_PYTHON_IMAGE). Each
		// server is granted its slot directory; git runs with the host
		// user's UID mapped (keep-id) so that git accepts the repository's
		// ownership.
		nodeImage, pyImage := os.Getenv("SMCP_AT17_NODE_IMAGE"), os.Getenv("SMCP_AT17_PYTHON_IMAGE")
		if nodeImage == "" || pyImage == "" {
			t.Fatal("the Enforced profile needs SMCP_AT17_NODE_IMAGE and SMCP_AT17_PYTHON_IMAGE (name@sha256:...)")
		}
		for _, d := range []string{data, files, repo} {
			if err := os.Chmod(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		extra += fmt.Sprintf(`
[[runtime.server]]
alias = "fs"
image = %q
[[runtime.server.mount]]
source = %q

[[runtime.server]]
alias = "git"
image = %q
userns = "keep-id"
allow_spawn = true
[[runtime.server.mount]]
source = %q
`, nodeImage, files, pyImage, repo)
	}
	g := newGateway(t, options{extra: extra})
	writeFile(t, g.sandbox, "notes.txt", "offline reference server\n", 0o644)
	g.trustAdd(filepath.Join(refpkg, "reference-test.pub"), "reference-test", "--classes", "low,moderate", "--expires", "30d")
	for _, p := range []string{"pkg-filesystem", "pkg-git"} {
		g.mustCtl("package", "install", filepath.Join(refpkg, p), "--enable")
	}
	g.writePolicy(at17Policy)
	g.start()
	g.scenario("AT-17")
	reqtest.Partial(t, "FR-12.2", "FR-14.9")

	cs := g.session(g.token(""))
	g.mustCall(cs, "fs_list_directory", map[string]any{"path": files}, "hello.txt")
	g.mustCall(cs, "git_git_status", map[string]any{"repo_path": repo}, "branch")
	g.mustCall(cs, "ref_read_file", map[string]any{"path": "notes.txt"}, "offline reference server")

	// An approval, offline.
	held := g.session(g.token("smcp:template:approval-demo"))
	done := make(chan error, 1)
	go func() {
		_, isErr, err := call(held, "ref_read_file", map[string]any{"path": "notes.txt"})
		if err == nil && isErr {
			err = fmt.Errorf("tool error")
		}
		done <- err
	}()
	var id string
	for deadline := time.Now().Add(30 * time.Second); id == "" && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		_, list := g.api("GET", "/api/v1/approvals?state=pending", nil)
		if items, _ := list["approvals"].([]any); len(items) > 0 {
			id, _ = items[0].(map[string]any)["id"].(string)
		}
	}
	if id == "" {
		t.Fatal("no pending approval")
	}
	g.mustCtl("approvals", "approve", id, "--yes")
	if err := <-done; err != nil {
		t.Fatalf("approved call: %v", err)
	}

	// Policy publication, the console page, a backup.
	pol := strings.Replace(at17Policy, "at17-r2", "at17-r3", 1)
	g.mustCtl("policy", "publish", writeFile(t, t.TempDir(), "p.json", pol, 0o644))
	resp, err := g.httpClient().Get(g.adminURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(strings.ToLower(string(page)), "<html") {
		t.Fatalf("console page: %d", resp.StatusCode)
	}
	pass := writeFile(t, t.TempDir(), "backup.pw", "offline backup passphrase\n", 0o600)
	g.mustCtl("backup", "--passphrase-file", pass)
	g.stop()
	if out := g.mustCtl("journal", "verify"); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
}
