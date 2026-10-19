package tunnel

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestHostRulesRuleset checks the SR-4.14-1 ruleset text and the nft
// invocations with a fake nft: the ports come from the listener
// addresses (sorted, deduplicated), the only accept is for loopback, and
// Install checks before it loads.
func TestHostRulesRuleset(t *testing.T) {
	reqtest.Partial(t, "SR-4.14-1")
	ports := HostRulePorts("127.0.0.1:8443", "127.0.0.1:8444", "", "127.0.0.1:8445", "bad", "127.0.0.1:8443", "127.0.0.1:9464")
	if !slices.Equal(ports, []int{8443, 8444, 8445, 9464}) {
		t.Fatalf("ports %v", ports)
	}
	r := HostRules(ports)
	for _, want := range []string{"table inet smcp_remote {", "delete table inet smcp_remote", "type filter hook input priority filter - 10; policy accept;",
		`iifname "lo" accept`, "tcp dport { 8443, 8444, 8445, 9464 } counter drop"} {
		if !strings.Contains(r, want) {
			t.Fatalf("ruleset lacks %q:\n%s", want, r)
		}
	}
	if strings.Count(r, "accept") != 2 {
		t.Fatalf("ruleset accepts more than loopback:\n%s", r)
	}

	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "nft")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\ncase \"$1\" in list) exit 1;; esac\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil { //nolint:gosec // executable test fake
		t.Fatal(err)
	}
	n := NFT{Bin: fake}
	if err := n.Install(context.Background(), nil); err == nil {
		t.Fatal("installed rules for no ports")
	}
	if err := n.Install(context.Background(), ports); err != nil {
		t.Fatal(err)
	}
	if err := n.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	if string(b) != "-c -f -\n-f -\nlist table inet smcp_remote\n" {
		t.Fatalf("calls %q", b)
	}
}
