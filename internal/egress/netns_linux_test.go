//go:build linux

package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The netns test needs root (network namespaces, veth, nftables). It runs
// in the linux-integration CI job through scripts/ci-egress-netns.sh and
// is skipped elsewhere.
const netnsEnv = "SMCP_EGRESS_NETNS_TEST"

const (
	testNS     = "smcp-egress-test"
	hostVeth   = "smcpeg0"
	nsVeth     = "smcpeg1"
	hostAddr   = "10.231.0.1"
	sandboxIP  = "10.231.0.2"
	targetAddr = "10.232.0.1" // on a dummy interface of the host: "outside" the sandbox
)

func sh(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func shQuiet(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

// fromSandbox runs this test binary inside the namespace as an HTTP
// client and returns its one-line result.
func fromSandbox(t *testing.T, target, proxy string) string {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", testNS, os.Args[0], "-test.run", "^TestNetnsHelperClient$", "-test.v")
	cmd.Env = append(os.Environ(), "SMCP_EGRESS_HELPER_URL="+target, "SMCP_EGRESS_HELPER_PROXY="+proxy)
	out, _ := cmd.CombinedOutput()
	for _, l := range strings.Split(string(out), "\n") {
		if i := strings.Index(l, "RESULT "); i >= 0 {
			return strings.TrimSpace(l[i+len("RESULT "):])
		}
	}
	t.Fatalf("helper produced no result:\n%s", out)
	return ""
}

// TestNetnsHelperClient is the client half of TestNetnsEnforcement; it
// does nothing unless started by it.
func TestNetnsHelperClient(t *testing.T) {
	target := os.Getenv("SMCP_EGRESS_HELPER_URL")
	if target == "" {
		t.Skip("helper for TestNetnsEnforcement")
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	if p := os.Getenv("SMCP_EGRESS_HELPER_PROXY"); p != "" {
		pu, err := url.Parse(p)
		if err != nil {
			t.Fatal(err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(target)
	if err != nil {
		fmt.Println("RESULT error", err)
		return
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("RESULT status=%d reason=%s body=%s\n", resp.StatusCode, resp.Header.Get(ReasonHeader), strings.TrimSpace(string(b)))
}

// TestNetnsEnforcement proves on a real kernel that, once the broker
// attaches a sandbox namespace, direct egress from it is blocked and
// brokered egress to a granted destination works, while an ungranted
// destination is refused by the broker. No Internet access is used: the
// destination is a local HTTP server on a host address outside the
// sandbox subnet.
func TestNetnsEnforcement(t *testing.T) {
	if os.Getenv(netnsEnv) != "1" {
		t.Skip("set " + netnsEnv + "=1 and run as root (scripts/ci-egress-netns.sh)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("needs root")
	}
	reqtest.Partial(t, "SR-4.5-1", "SR-4.5-2")

	shQuiet("ip", "netns", "del", testNS)
	shQuiet("ip", "link", "del", hostVeth)
	shQuiet("ip", "link", "del", "smcpdst")
	sh(t, "ip", "netns", "add", testNS)
	t.Cleanup(func() {
		shQuiet("ip", "netns", "del", testNS)
		shQuiet("ip", "link", "del", hostVeth)
		shQuiet("ip", "link", "del", "smcpdst")
	})
	sh(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	sh(t, "ip", "link", "set", nsVeth, "netns", testNS)
	sh(t, "ip", "addr", "add", hostAddr+"/24", "dev", hostVeth)
	sh(t, "ip", "link", "set", hostVeth, "up")
	nsx := func(args ...string) { sh(t, append([]string{"ip", "netns", "exec", testNS}, args...)...) }
	nsx("ip", "link", "set", "lo", "up")
	nsx("ip", "addr", "add", sandboxIP+"/24", "dev", nsVeth)
	nsx("ip", "link", "set", nsVeth, "up")
	nsx("ip", "route", "add", "default", "via", hostAddr)
	sh(t, "ip", "link", "add", "smcpdst", "type", "dummy")
	sh(t, "ip", "addr", "add", targetAddr+"/32", "dev", "smcpdst")
	sh(t, "ip", "link", "set", "smcpdst", "up")

	serve := func(body string) string {
		ln, err := net.Listen("tcp", targetAddr+":0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, body) }),
			ReadHeaderTimeout: 5 * time.Second}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		return "http://" + ln.Addr().String() + "/"
	}
	granted, other := serve("granted-ok"), serve("other-ok")
	gu, _ := url.Parse(granted)
	gp, _ := portOf(gu.Port(), 0)

	// Baseline: without the broker's rules the sandbox reaches both.
	if r := fromSandbox(t, granted, ""); !strings.Contains(r, "body=granted-ok") {
		t.Fatalf("baseline direct egress did not work, the test network is broken: %s", r)
	}

	ev := &audit.Memory{}
	b, err := New(Options{Grants: NewStaticGrants([]Grant{{Server: "web", Host: targetAddr, Ports: []int{gp}, Methods: []string{"GET"},
		Class: ClassAPI, Addresses: []netip.Addr{netip.MustParseAddr(targetAddr)}}}), Evidence: ev, ProxyEnv: true, Recent: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	att, err := b.Attach(context.Background(), pipeline.EgressRequest{Alias: "web",
		Network: &pipeline.EgressNetwork{NetNS: "/run/netns/" + testNS, ListenAddr: netip.MustParseAddr(hostAddr)}})
	if err != nil {
		t.Fatal(err)
	}
	if !att.Enforced {
		t.Fatal("attachment not enforced")
	}
	out, _ := exec.Command("ip", "netns", "exec", testNS, "nft", "list", "table", "inet", TableName).CombinedOutput()
	t.Logf("rules in the sandbox namespace:\n%s", out)
	proxy := att.Env["HTTP_PROXY"]

	if r := fromSandbox(t, granted, ""); !strings.HasPrefix(r, "error") {
		t.Fatalf("direct egress to the granted destination was not blocked: %s", r)
	}
	if r := fromSandbox(t, other, ""); !strings.HasPrefix(r, "error") {
		t.Fatalf("direct egress to another destination was not blocked: %s", r)
	}
	if r := fromSandbox(t, "http://"+hostAddr+":22/", ""); !strings.HasPrefix(r, "error") {
		t.Fatalf("a host service other than the broker was reachable: %s", r)
	}
	if r := fromSandbox(t, granted, proxy); !strings.Contains(r, "status=200") || !strings.Contains(r, "body=granted-ok") {
		t.Fatalf("brokered egress to the granted destination failed: %s", r)
	}
	if r := fromSandbox(t, other, proxy); !strings.Contains(r, "status=403") || !strings.Contains(r, ReasonNoGrant) {
		t.Fatalf("brokered egress to an ungranted destination was not refused: %s", r)
	}
	recs := b.Recent()
	if len(recs) != 2 || recs[1].Decision != DecisionAllowed || recs[1].Address != targetAddr || recs[0].Reason != ReasonNoGrant {
		t.Fatalf("records %+v", recs)
	}

	// Detach removes the rules: direct egress works again, which shows the
	// broker's rules were what blocked it.
	if err := att.Close(); err != nil {
		t.Fatal(err)
	}
	if r := fromSandbox(t, granted, ""); !strings.Contains(r, "body=granted-ok") {
		t.Fatalf("after detach: %s", r)
	}
}
