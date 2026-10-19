//go:build linux

package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The namespace test needs root (network namespaces, veth, nftables). It
// runs in the linux-integration CI job through scripts/ci-egress-netns.sh
// and is skipped elsewhere.
const hostRulesEnv = "SMCP_REMOTE_NFT_TEST"

const (
	rtNS       = "smcp-remote-test"
	rtHostVeth = "smcprt0"
	rtNSVeth   = "smcprt1"
	rtHostAddr = "10.234.0.1"
	rtNSAddr   = "10.234.0.2"
	rtOpenPort = 9999 // not a Gateway port: stays reachable
)

func rtSh(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil { //nolint:gosec // fixed test commands
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// TestHostRulesInNamespace is the kernel half of SR-4.14-1. A network
// namespace stands for the Enforced host and the root namespace for
// another host on its network (a veth pair between them). Inside, a
// helper listens on every address at the default CP-02 (8443), CP-03
// (8444), CP-48 (8445) and CP-51 (9464) ports, which is worse than the
// Gateway's loopback binding, and on one other port. After the ruleset of
// `smcpctl remote enable` (HostRules, loaded by NFT.Install exactly as the
// command does; cmd/smcpctl TestRemoteEnableInstallsHostRules shows the
// command loads this ruleset and nothing else) is installed in the
// namespace:
//
//   - a connection from the other host to each Gateway port is dropped
//     (the connect times out; no reset is sent);
//   - the other port still accepts, so the rules add no exception and
//     change nothing else;
//   - inside the namespace, a client on loopback (the tunnel connector)
//     reaches the CP-48 listener and the others;
//   - removing the table restores the previous behavior.
func TestHostRulesInNamespace(t *testing.T) {
	if os.Getenv(hostRulesEnv) != "1" {
		t.Skip("set " + hostRulesEnv + "=1 and run as root (scripts/ci-egress-netns.sh)")
	}
	reqtest.Verifies(t, "SR-4.14-1")
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal("nft not found")
	}
	_ = exec.Command("ip", "netns", "del", rtNS).Run()
	_ = exec.Command("ip", "link", "del", rtHostVeth).Run()
	rtSh(t, "ip", "netns", "add", rtNS)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", rtNS).Run()
		_ = exec.Command("ip", "link", "del", rtHostVeth).Run()
	})
	rtSh(t, "ip", "link", "add", rtHostVeth, "type", "veth", "peer", "name", rtNSVeth)
	rtSh(t, "ip", "link", "set", rtNSVeth, "netns", rtNS)
	rtSh(t, "ip", "addr", "add", rtHostAddr+"/24", "dev", rtHostVeth)
	rtSh(t, "ip", "link", "set", rtHostVeth, "up")
	rtSh(t, "ip", "netns", "exec", rtNS, "ip", "addr", "add", rtNSAddr+"/24", "dev", rtNSVeth)
	rtSh(t, "ip", "netns", "exec", rtNS, "ip", "link", "set", rtNSVeth, "up")
	rtSh(t, "ip", "netns", "exec", rtNS, "ip", "link", "set", "lo", "up")

	ports := HostRulePorts("127.0.0.1:8443", "127.0.0.1:8444", "127.0.0.1:8445", "127.0.0.1:9464")
	all := append(append([]int{}, ports...), rtOpenPort)
	list := make([]string, len(all))
	for i, p := range all {
		list[i] = strconv.Itoa(p)
	}
	helper := exec.Command("ip", "netns", "exec", rtNS, os.Args[0], "-test.run", "^TestHostRulesHelperListen$", "-test.v") //nolint:gosec // this test binary
	helper.Env = append(os.Environ(), "SMCP_HOSTRULES_LISTEN="+strings.Join(list, ","))
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = helper.Process.Kill(); _ = helper.Wait() })
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "LISTENING") {
				ready <- true
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("listener helper exited")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("listener helper not ready")
	}

	reach := func(port int) error {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(rtNSAddr, strconv.Itoa(port)), 1500*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err
	}
	for _, p := range all {
		if err := reach(p); err != nil {
			t.Fatalf("before the rules, port %d is not reachable from the other host: %v", p, err)
		}
	}

	n := NFT{Bin: nft, Prefix: []string{"ip", "netns", "exec", rtNS}}
	ctx := context.Background()
	if err := n.Install(ctx, ports); err != nil {
		t.Fatal(err)
	}
	if listed, err := n.List(ctx); err != nil || !strings.Contains(listed, "drop") {
		t.Fatalf("table not installed: %v\n%s", err, listed)
	}
	for _, p := range ports {
		err := reach(p)
		var ne net.Error
		if err == nil || !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("port %d from the other host: want a dropped connection (timeout), got %v", p, err)
		}
	}
	if err := reach(rtOpenPort); err != nil {
		t.Errorf("port %d (not a Gateway port) was affected: %v", rtOpenPort, err)
	}
	// The tunnel connector on the host reaches the listeners on loopback.
	dial := exec.Command("ip", "netns", "exec", rtNS, os.Args[0], "-test.run", "^TestHostRulesHelperDial$", "-test.v") //nolint:gosec // this test binary
	var targets []string
	for _, p := range ports {
		targets = append(targets, fmt.Sprintf("127.0.0.1:%d", p))
	}
	dial.Env = append(os.Environ(), "SMCP_HOSTRULES_DIAL="+strings.Join(targets, ","))
	out, _ := dial.CombinedOutput()
	if !strings.Contains(string(out), "RESULT ok") {
		t.Errorf("loopback client inside the host could not reach the listeners:\n%s", out)
	}
	if err := n.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if err := reach(8445); err != nil {
		t.Errorf("after removing the table, port 8445 is still blocked: %v", err)
	}
}

// TestHostRulesHelperListen listens on every address at the ports in
// $SMCP_HOSTRULES_LISTEN until killed (run inside the namespace).
func TestHostRulesHelperListen(t *testing.T) {
	spec := os.Getenv("SMCP_HOSTRULES_LISTEN")
	if spec == "" {
		t.Skip("helper")
	}
	for _, p := range strings.Split(spec, ",") {
		l, err := net.Listen("tcp", ":"+p)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	fmt.Println("LISTENING")
	select {}
}

// TestHostRulesHelperDial connects to each address in
// $SMCP_HOSTRULES_DIAL and prints "RESULT ok" when all accept.
func TestHostRulesHelperDial(t *testing.T) {
	spec := os.Getenv("SMCP_HOSTRULES_DIAL")
	if spec == "" {
		t.Skip("helper")
	}
	for _, a := range strings.Split(spec, ",") {
		c, err := net.DialTimeout("tcp", a, 2*time.Second)
		if err != nil {
			fmt.Println("RESULT fail", a, err)
			return
		}
		c.Close()
	}
	fmt.Println("RESULT ok")
}
