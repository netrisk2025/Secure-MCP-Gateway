//go:build linux

package acceptance

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/posixacl"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

const secretDeliveryPolicy = `{
  "revision": "secret-delivery-r1",
  "framework_profiles": {"dev": {"templates": ["read-only", "approval-demo"], "default_template": "read-only"}},
  "templates": {
    "read-only": {"rules": [
      {"id": "ref", "server": "ref", "tools": ["echo"]},
      {"id": "sone", "server": "sone", "tools": ["fetch", "echo"]},
      {"id": "sfile", "server": "sfile", "tools": ["file_sha256", "read_file", "echo"]}
    ]},
    "approval-demo": {"rules": [{"id": "demo", "server": "ref", "tools": ["echo"]}]}
  }
}`

// memScan is run as root (sudo -n python3 -I -c memScan PID NEEDLE_FILE):
// it reads the process's environment, command line and every readable
// memory mapping and prints the number of bytes read, then one line per
// place where the needle appears.
const memScan = `
import re, sys
pid, needle = sys.argv[1], open(sys.argv[2], 'rb').read()
hits, scanned = [], 0
for name in ('environ', 'cmdline'):
    with open('/proc/%s/%s' % (pid, name), 'rb') as f:
        if needle in f.read():
            hits.append(name)
mem = open('/proc/%s/mem' % pid, 'rb', 0)
for line in open('/proc/%s/maps' % pid):
    m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S+)', line)
    if not m or m.group(3)[0] != 'r' or '[vvar' in line or '[vsyscall' in line:
        continue
    a, b = int(m.group(1), 16), int(m.group(2), 16)
    tail = b''
    while a < b:
        n = min(16 << 20, b - a)
        try:
            mem.seek(a)
            data = mem.read(n)
        except (OSError, ValueError, OverflowError):
            break
        scanned += len(data)
        if needle in tail + data:
            hits.append(line.strip())
            break
        tail = data[-len(needle):]
        a += n
print(scanned)
for h in hits:
    print(h)
`

// fileScan is run as root (sudo -n python3 -I -c fileScan NEEDLE_FILE
// PATH...): it reads every regular file under the paths and prints the
// number of files read, then each file that contains the needle.
const fileScan = `
import os, sys
needle = open(sys.argv[1], 'rb').read()
files, hits = 0, []
def scan(p):
    global files
    try:
        with open(p, 'rb') as f:
            files += 1
            if needle in f.read():
                hits.append(p)
    except OSError:
        pass
for root in sys.argv[2:]:
    if os.path.isfile(root):
        scan(root)
        continue
    for d, _, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p) and not os.path.islink(p):
                scan(p)
print(files)
for h in hits:
    print(h)
`

// TestEnforcedSecretDelivery runs the S1, S2 and S3 secret deliveries
// (FR-6.6, FR-6.7, FR-6.8) end to end through the real smcpd, the Secret
// Broker, the Egress Broker and rootless Podman sandboxes in the Enforced
// profile:
//
//   - S1: the EGRESS fixture of smcp-hostile calls an HTTPS fixture API
//     through its broker endpoint; the API receives the Authorization
//     header with the secret, and the instance's environment (Podman's
//     container configuration and /proc/<pid>/environ of every process
//     of the container), a dump of every readable memory mapping of those
//     processes and every file of every mount of the container lack the
//     value. A control string from the fixture binary is found by the
//     same memory scan, so the scan reads memory.
//   - S2: the sandbox probe reads its per-call file at /smcp/secrets
//     during a call of the permitted tool (its SHA-256 matches the
//     secret); after the call the file is gone on the host and inside the
//     container. The file lives in the instance's own directory on a
//     tmpfs, mounted only into that instance's container.
//   - S3: the launch-time file exists in the same instance directory and
//     is readable in the container while the instance runs; when the
//     Gateway stops (instance teardown) the instance directory is gone.
//
// The test needs the Enforced profile, rootless Podman, passwordless sudo
// and python3; it is skipped in the Standalone profile.
func TestEnforcedSecretDelivery(t *testing.T) {
	needBinaries(t)
	if requestedProfile() != reqtest.Enforced {
		t.Skip("secret deliveries through the sandbox need SMCP_ACCEPTANCE_PROFILE=enforced (rootless Podman)")
	}
	for _, tool := range []string{"podman", "sudo", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
	}
	if out, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Fatalf("passwordless sudo: %v %s", err, out)
	}
	probeBin := filepath.Join(t.TempDir(), "sandbox-probe")
	build := exec.Command("go", "build", "-trimpath", "-o", probeBin, "../../scripts/sandbox-probe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build sandbox-probe: %v\n%s", err, out)
	}
	if err := os.Chmod(filepath.Dir(probeBin), 0o755); err != nil {
		t.Fatal(err)
	}

	s1 := "s1-" + randomHex(t, 20)
	s23 := "s23-" + randomHex(t, 20)

	// The fixture API behind the S1 header grant.
	cert, caPEM := testCA(t, "web.test")
	var mu sync.Mutex
	var sawAuth []string
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		io.WriteString(w, "api-ok")
	}))
	api.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	api.StartTLS()
	defer api.Close()
	aport := api.Listener.Addr().(*net.TCPAddr).Port
	dns := newDNSFixture(t, map[string][]string{"web.test": {"127.0.0.1"}})

	priv := t.TempDir()
	dir := t.TempDir()
	caFile := writeFile(t, dir, "egress-ca.pem", string(caPEM), 0o644)
	pass := writeFile(t, priv, "vault.pass", randomHex(t, 24), 0o600)
	runtimeBase := "/dev/shm"
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" && secrets.IsTmpfs(x) {
		runtimeBase = x
	}
	runtimeDir := filepath.Join(runtimeBase, "smcp-delivery-"+randomHex(t, 6))
	t.Cleanup(func() { os.RemoveAll(runtimeDir) })
	usePolicy := writeFile(t, priv, "secret-use.json", fmt.Sprintf(`{
  "revision": "delivery-1",
  "slots": [
    {"server": "sone", "name": "api", "modes": ["S1"], "header": "Authorization", "header_template": "Bearer {secret}", "destination": "web.test:%d"},
    {"server": "sfile", "name": "percall", "modes": ["S2"], "file_env": "PERCALL_FILE"},
    {"server": "sfile", "name": "launch", "modes": ["S3"], "file_env": "LAUNCH_FILE"}
  ],
  "policies": [
    {"id": "s1", "secret": "s1-token", "server": "sone", "slot": "api", "mode": "S1", "tools": ["*"], "purpose": "fixture API"},
    {"id": "s2", "secret": "s23-token", "server": "sfile", "slot": "percall", "mode": "S2", "tools": ["file_sha256"], "purpose": "per-call file"},
    {"id": "s3", "secret": "s23-token", "server": "sfile", "slot": "launch", "mode": "S3", "tools": ["*"], "purpose": "launch file"}
  ]
}`, aport), 0o600)

	extra := fmt.Sprintf(`
[[server]]
alias = "sone"
command = %q
args = ["-fixture", "EGRESS"]

[[server]]
alias = "sfile"
command = %q

[[runtime.server]]
alias = "sone"
network = "egress"

[[runtime.server]]
alias = "sfile"

[egress]
enabled = true
resolvers = [%q]
ca_file = %q

[[egress.grant]]
server = "sone"
host = "web.test"
ports = [%d]
methods = ["GET"]
addresses = ["127.0.0.1"]
endpoint_env = "WEB_URL"

[secrets]
key_source = "passphrase"
passphrase_file = %q
runtime_dir = %q
`, filepath.Join(binDir, "smcp-hostile"), probeBin, dns.addr(), caFile, aport, pass, runtimeDir)
	g := newGateway(t, options{extra: extra})
	g.writePolicy(secretDeliveryPolicy)
	// Secrets are stored through the control API of a running Gateway;
	// the Secret Use Policy is added afterwards, so the instances are
	// launched with their deliveries when the Gateway starts again.
	g.mustCtl("secrets", "init", "--key-source", "passphrase", "--passphrase-file", pass)
	g.start()
	g.mustCtl("secrets", "set", "s1-token", "--value-file", writeFile(t, priv, "s1", s1, 0o600))
	g.mustCtl("secrets", "set", "s23-token", "--value-file", writeFile(t, priv, "s23", s23, 0o600))
	g.stop()
	g.appendConfig(fmt.Sprintf("use_policy_file = %q\n", usePolicy)) // the [secrets] table is the last one
	g.start()
	if g.profile() != reqtest.Enforced {
		t.Fatalf("the Gateway reports the %s profile", g.profile())
	}
	reqtest.Verifies(t, "FR-6.6", "FR-6.7", "FR-6.8")
	cs := g.session(g.token(""))

	// --- S1 -------------------------------------------------------------
	text, isErr, err := call(cs, "sone_fetch", map[string]any{"via": "endpoint", "env": "WEB_URL", "path": "/v1/data"})
	if err != nil || isErr {
		t.Fatalf("sone_fetch: %v %v %q\n%s", err, isErr, text, lastDenials(g))
	}
	var p probe
	if err := json.Unmarshal([]byte(text), &p); err != nil || p.Status != 200 || p.Body != "api-ok" {
		t.Fatalf("sone_fetch: %q", text)
	}
	mu.Lock()
	got := append([]string(nil), sawAuth...)
	mu.Unlock()
	if len(got) != 1 || got[0] != "Bearer "+s1 {
		t.Fatalf("the fixture API received Authorization %q, want the S1 header", got)
	}
	needle := writeFile(t, priv, "needle", s1, 0o600)
	sone := container(t, "sone")
	inspect := podmanOut(t, "inspect", sone)
	if strings.Contains(inspect, s1) {
		t.Fatal("the S1 value is in the container configuration (environment, arguments, labels or mounts)")
	}
	pids := strings.Fields(podmanOut(t, "top", sone, "hpid"))
	if len(pids) < 2 { // header plus at least one process
		t.Fatalf("podman top %s: %v", sone, pids)
	}
	control := writeFile(t, priv, "control", "Send one HTTP request through the Egress Broker", 0o600)
	controlSeen := false
	for _, pid := range pids[1:] {
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		scanned, hits := sudoScan(t, memScan, pid, needle)
		t.Logf("S1 instance process %s: %d bytes of memory scanned", pid, scanned)
		if scanned == 0 {
			t.Fatalf("no memory of process %s was read", pid)
		}
		if len(hits) > 0 {
			t.Fatalf("the S1 value is in process %s of the instance: %v", pid, hits)
		}
		if _, ch := sudoScan(t, memScan, pid, control); len(ch) > 0 {
			controlSeen = true
		}
	}
	if !controlSeen {
		t.Fatal("the memory scan did not find the control string of the fixture binary; it does not read memory")
	}
	var mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	}
	if err := json.Unmarshal([]byte(podmanOut(t, "inspect", "--format", "{{json .Mounts}}", sone)), &mounts); err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, m := range mounts {
		if m.Source != "" {
			sources = append(sources, m.Source)
		}
	}
	if len(sources) == 0 {
		t.Fatal("the S1 instance has no mounts to check")
	}
	files, hits := sudoScan(t, fileScan, append([]string{needle}, sources...)...)
	t.Logf("S1 instance mounts %v: %d files scanned", sources, files)
	if files == 0 || len(hits) > 0 {
		t.Fatalf("mount files scanned %d, files holding the S1 value %v", files, hits)
	}
	// The S1 instance has an instance directory of its own (every
	// instance with secret bindings gets one), which stays empty: S1
	// writes no file. It mounts no other instance's directory.
	for _, m := range mounts {
		if !strings.HasPrefix(m.Source, runtimeDir+"/") {
			continue
		}
		if !strings.HasPrefix(filepath.Base(m.Source), "sone-") || m.Destination != "/smcp/secrets" {
			t.Fatalf("the S1 instance mounts another secret directory: %+v", m)
		}
		if entries, err := os.ReadDir(m.Source); err != nil || len(entries) != 0 {
			t.Fatalf("the S1 instance directory %s holds %v (%v)", m.Source, entries, err)
		}
	}

	// --- S2 and S3 ------------------------------------------------------
	sum := "sha256:" + hex.EncodeToString(sha256Of(s23))
	instDirs, _ := filepath.Glob(filepath.Join(runtimeDir, "sfile-*"))
	if len(instDirs) != 1 {
		t.Fatalf("instance directories of sfile: %v", instDirs)
	}
	inst := instDirs[0]
	if !secrets.IsTmpfs(inst) {
		t.Fatalf("%s is not on a tmpfs", inst)
	}
	// Owner only, except that a POSIX ACL may let the instance's own UID
	// in (the group bits then show the ACL mask, at most search).
	if st, err := os.Stat(inst); err != nil || st.Mode().Perm()&0o067 != 0 || st.Mode().Perm()&0o700 != 0o700 {
		t.Fatalf("instance directory %s: %v %v", inst, st.Mode(), err)
	}
	if a, err := posixacl.Get(inst); err == nil {
		others := 0
		for uid := range a.Users() {
			if uid != os.Getuid() {
				others++
			}
		}
		if others > 1 {
			t.Fatalf("instance directory %s grants %d other users: %v", inst, others, a.Users())
		}
	}
	sfile := container(t, "sfile")
	var fmounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	}
	if err := json.Unmarshal([]byte(podmanOut(t, "inspect", "--format", "{{json .Mounts}}", sfile)), &fmounts); err != nil {
		t.Fatal(err)
	}
	secretMounts := 0
	for _, m := range fmounts {
		if m.Destination == "/smcp/secrets" {
			secretMounts++
			if m.Source != inst {
				t.Fatalf("the probe's secret mount is %s, not its instance directory %s", m.Source, inst)
			}
		}
	}
	if secretMounts != 1 {
		t.Fatalf("secret mounts of the probe: %+v", fmounts)
	}
	mountinfo := callText(t, cs, "sfile_read_file", map[string]any{"path": "/proc/self/mountinfo"})
	tmpfsMount := false
	for _, line := range strings.Split(mountinfo, "\n") {
		if f := strings.Fields(line); len(f) > 4 && f[4] == "/smcp/secrets" && strings.Contains(line, " - tmpfs ") {
			tmpfsMount = true
		}
	}
	if !tmpfsMount {
		t.Fatalf("/smcp/secrets is not a tmpfs mount in the probe's container:\n%s", mountinfo)
	}
	// S3: present from launch.
	if _, err := os.Stat(filepath.Join(inst, "launch")); err != nil {
		t.Fatalf("S3 file at launch: %v", err)
	}
	// S2: absent between calls, present during the permitted call.
	if _, err := os.Stat(filepath.Join(inst, "percall")); !os.IsNotExist(err) {
		t.Fatalf("S2 file before the call: %v", err)
	}
	if got := callText(t, cs, "sfile_file_sha256", map[string]any{"path": "/smcp/secrets/percall"}); got != sum {
		t.Fatalf("S2 file during the call: %q, want %q", got, sum)
	}
	if _, err := os.Stat(filepath.Join(inst, "percall")); !os.IsNotExist(err) {
		t.Fatalf("S2 file after the call: %v", err)
	}
	if got := callText(t, cs, "sfile_read_file", map[string]any{"path": "/smcp/secrets/percall"}); !strings.HasPrefix(got, "blocked:") {
		t.Fatalf("S2 file inside the container after the call: %q", got)
	}
	if got := callText(t, cs, "sfile_file_sha256", map[string]any{"path": "/smcp/secrets/launch"}); got != sum {
		t.Fatalf("S3 file while the instance runs: %q, want %q", got, sum)
	}
	if _, err := os.Stat(filepath.Join(inst, "percall")); !os.IsNotExist(err) {
		t.Fatalf("S2 file after the second call: %v", err)
	}
	// S3: gone at teardown.
	g.stop()
	if _, err := os.Stat(inst); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(inst)
		t.Fatalf("instance directory after teardown: %v %v", err, entries)
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func sha256Of(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// podmanOut runs podman and returns its standard output.
func podmanOut(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("podman", args...).Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("podman %v: %v %s", args, err, stderr)
	}
	return string(out)
}

// container returns the name of the one running Gateway container of a
// server alias.
func container(t *testing.T, alias string) string {
	t.Helper()
	var names []string
	for _, n := range strings.Fields(podmanOut(t, "ps", "--filter", "label=smcp.managed=1", "--format", "{{.Names}}")) {
		if strings.HasPrefix(n, "smcp-"+alias+"-") {
			names = append(names, n)
		}
	}
	if len(names) != 1 {
		t.Fatalf("containers of %s: %v", alias, names)
	}
	return names[0]
}

// sudoScan runs one of the scan scripts as root and returns the count it
// prints first and the hits that follow.
func sudoScan(t *testing.T, script string, args ...string) (int64, []string) {
	t.Helper()
	out, err := exec.Command("sudo", append([]string{"-n", "python3", "-I", "-c", script}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("scan %v: %v\n%s", args, err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	n, err := strconv.ParseInt(lines[0], 10, 64)
	if err != nil {
		t.Fatalf("scan output %q", out)
	}
	return n, lines[1:]
}

// callText calls a tool and returns its text, failing on any error.
func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	text, isErr, err := call(cs, name, args)
	if err != nil || isErr {
		t.Fatalf("%s %v: %v %v %q", name, args, err, isErr, text)
	}
	return text
}
