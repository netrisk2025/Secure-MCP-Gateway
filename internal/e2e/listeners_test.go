package e2e

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

// TestHarnessListenerSet is FR-1.1: a Gateway with the UDS Harness Profile
// enabled listens on exactly the CP-02 TLS harness listener, the CP-02
// UDS socket and the CP-03 admin listener; the listening sockets of the
// process are enumerated from the kernel (/proc on Linux, lsof on macOS).
// A harness then completes a tools/list over the socket. The Remote Access
// listener (FR-16) and the metrics listener are not configured here.
func TestHarnessListenerSet(t *testing.T) {
	reqtest.Verifies(t, "FR-1.1")
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("socket enumeration needs /proc or lsof")
	}
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("lsof"); err != nil {
			t.Skip("lsof not installed")
		}
	}
	dir := testport.SocketDir(t)
	sock := filepath.Join(dir, "h.sock")
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	grp, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("primary group: %v", err)
	}
	const key = "uds harness key 0123456789"
	f := startWith(t, "", fmt.Sprintf("[uds]\nenabled = true\npath = %q\ngroup = %q\n[[uds.peer]]\nuid = %d\nprincipal = \"cc\"\nkey_hash = %q\n",
		sock, grp.Name, os.Getuid(), mustHash(t, key)))

	tcp, unix := listeningSockets(t)
	wantTCP := []string{f.cfg.Listener.Address, f.cfg.AdminListener.Address}
	sort.Strings(wantTCP)
	sort.Strings(tcp)
	if strings.Join(tcp, " ") != strings.Join(wantTCP, " ") {
		t.Fatalf("listening TCP sockets %v, want %v", tcp, wantTCP)
	}
	resolved, _ := filepath.EvalSymlinks(dir)
	if len(unix) != 1 || (unix[0] != sock && unix[0] != filepath.Join(resolved, "h.sock")) {
		t.Fatalf("listening Unix sockets %v, want [%s]", unix, sock)
	}

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, `{"jsonrpc":"2.0","id":0,"method":%q,"params":{"key":%q}}`+"\n", edge.MethodUDSAuthenticate, key)
	fmt.Fprintf(c, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{%s}}`+"\n", modernMeta)
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	for i := 0; i < 2; i++ {
		if !sc.Scan() {
			t.Fatalf("socket closed: %v", sc.Err())
		}
		if line := sc.Text(); strings.Contains(line, `"error"`) || (i == 1 && !strings.Contains(line, `"t_echo"`)) {
			t.Fatalf("reply %d: %s", i, line)
		}
	}
}

// listeningSockets returns the listening TCP addresses and Unix socket
// paths of this process.
func listeningSockets(t *testing.T) (tcp, unix []string) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		pid := strconv.Itoa(os.Getpid())
		out, err := exec.Command("lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn").Output()
		if err != nil && len(out) == 0 {
			t.Fatalf("lsof: %v", err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			if n, ok := strings.CutPrefix(l, "n"); ok {
				tcp = append(tcp, n)
			}
		}
		out, _ = exec.Command("lsof", "-nP", "-a", "-p", pid, "-U", "-Fn").Output()
		for _, l := range strings.Split(string(out), "\n") {
			if n, ok := strings.CutPrefix(l, "n"); ok && strings.HasPrefix(n, "/") {
				unix = append(unix, n)
			}
		}
		return tcp, unix
	}
	inodes := map[string]bool{}
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if l, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil {
			if in, ok := strings.CutPrefix(l, "socket:["); ok {
				inodes[strings.TrimSuffix(in, "]")] = true
			}
		}
	}
	for _, file := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(raw), "\n")[1:] {
			fs := strings.Fields(l)
			if len(fs) < 10 || fs[3] != "0A" || !inodes[fs[9]] { // 0A: LISTEN
				continue
			}
			tcp = append(tcp, procAddr(fs[1]))
		}
	}
	raw, err := os.ReadFile("/proc/self/net/unix")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(raw), "\n")[1:] {
		fs := strings.Fields(l)
		// Num RefCount Protocol Flags Type St Inode Path; flag 00010000 is
		// __SO_ACCEPTCON (listening).
		if len(fs) < 8 || fs[3] != "00010000" || !inodes[fs[6]] {
			continue
		}
		unix = append(unix, fs[7])
	}
	return tcp, unix
}

// procAddr turns a /proc/net/tcp address (little-endian hex IPv4 or IPv6
// words, hex port) into host:port.
func procAddr(s string) string {
	h, p, _ := strings.Cut(s, ":")
	b, _ := hex.DecodeString(h)
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	port, _ := strconv.ParseUint(p, 16, 16)
	return net.JoinHostPort(net.IP(b).String(), strconv.FormatUint(port, 10))
}
