package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/tunnel"
)

// TestRemoteEnableInstallsHostRules is the smcpctl half of SR-4.14-1 with
// a fake nft that records its arguments and the ruleset it is given:
// remote enable checks and loads the nftables table that drops every
// non-loopback connection to the CP-02, CP-03, CP-48 and CP-51 ports
// before the remote listener exists, adds no other firewall rule or
// exception, and remote disable removes the table. A rejected ruleset
// leaves remote access disabled. The kernel half (the rules drop the
// connections and the tunnel connector on the host still reaches the
// remote listener) is internal/tunnel TestHostRulesInNamespace.
func TestRemoteEnableInstallsHostRules(t *testing.T) {
	reqtest.Partial(t, "SR-4.14-1")
	// nft is a fake, so the host may be any; --host-rules nftables is
	// refused off Linux (TestHostRulesDecision).
	defer func(old string) { hostGOOS = old }(hostGOOS)
	hostGOOS = "linux"
	g := gwtest.Start(t, remoteTOML)
	bin, log := fakeCLI(t, "nft", `if [ "$1" = "-c" ] || [ "$1" = "-f" ]; then cat >> "$(dirname "$0")/rules.log"; fi
if [ "$1" = "list" ]; then exit 0; fi
`)
	t.Setenv("SMCP_NFT", bin)
	public := g.Tunnel(func() string { return "203.0.113.5" })
	code, out, errs := rctl(t, "remote", "enable", "--config", g.CfgPath, "--provider", "manual", "--public-url", public, "--host-rules", "nftables")
	if code != 0 || !strings.Contains(out, "host rules: nftables table inet smcp_remote") {
		t.Fatalf("enable: %d %s %s", code, out, errs)
	}
	calls, _ := os.ReadFile(log)
	if !strings.HasPrefix(string(calls), "-c -f -\n-f -\n") {
		t.Fatalf("nft calls: %q", calls)
	}
	rules, _ := os.ReadFile(strings.TrimSuffix(log, "calls.log") + "rules.log")
	ports := tunnel.HostRulePorts(g.Config.Listener.Address, g.Config.AdminListener.Address, g.Config.Remote.Address, g.Config.Metrics.Address)
	if len(ports) != 4 {
		t.Fatalf("ports %v", ports)
	}
	want := tunnel.HostRules(ports)
	if string(rules) != want+want {
		t.Fatalf("ruleset:\n%s\nwant (twice):\n%s", rules, want)
	}
	for _, p := range ports {
		if !strings.Contains(want, fmt.Sprint(p)) {
			t.Fatalf("port %d missing", p)
		}
	}
	// No exception: the only accept is for loopback, the listener ports
	// are dropped.
	if strings.Count(want, "accept") != 2 || !strings.Contains(want, `iifname "lo" accept`) || !strings.Contains(want, "drop") {
		t.Fatalf("ruleset opens something:\n%s", want)
	}
	if !g.Remote.Status().Enabled {
		t.Fatal("remote access not enabled")
	}
	if code, out, errs := rctl(t, "remote", "disable", "--config", g.CfgPath); code != 0 || !strings.Contains(out, "host rules removed") {
		t.Fatalf("disable: %d %s %s", code, out, errs)
	}
	calls, _ = os.ReadFile(log)
	if !strings.Contains(string(calls), "delete table inet smcp_remote") {
		t.Fatalf("table not removed: %q", calls)
	}

	// A ruleset nft rejects: nothing is enabled.
	bad, _ := fakeCLI(t, "nft", "echo 'Error: syntax error' >&2; exit 1\n")
	t.Setenv("SMCP_NFT", bad)
	if code, _, errs := rctl(t, "remote", "enable", "--config", g.CfgPath, "--provider", "manual", "--public-url", public, "--host-rules", "nftables"); code == 0 || !strings.Contains(errs, "remote access not enabled") {
		t.Fatalf("enable with rejected rules: %d %s", code, errs)
	}
	if g.Remote.Status().Enabled {
		t.Fatal("remote access enabled without its host rules")
	}
}

// TestHostRulesDecision: the Enforced profile always installs the rules
// and refuses --host-rules off; the Standalone profile installs them only
// on request on Linux; nftables is refused elsewhere (macOS uses pf, see
// docs/remote-access.md).
func TestHostRulesDecision(t *testing.T) {
	reqtest.Partial(t, "SR-4.14-1")
	for _, c := range []struct {
		mode, profile, goos string
		want, err           bool
	}{
		{"auto", "enforced", "linux", true, false},
		{"nftables", "enforced", "linux", true, false},
		{"off", "enforced", "linux", false, true},
		{"auto", "standalone", "linux", false, false},
		{"nftables", "standalone", "linux", true, false},
		{"off", "standalone", "darwin", false, false},
		{"auto", "standalone", "darwin", false, false},
		{"nftables", "standalone", "darwin", false, true},
		{"pf", "standalone", "darwin", false, true},
	} {
		got, err := hostRulesWanted(c.mode, c.profile, c.goos)
		if got != c.want || (err != nil) != c.err {
			t.Errorf("%+v: %v %v", c, got, err)
		}
	}
}
