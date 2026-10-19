package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// HostRulesTable is the nftables table that `smcpctl remote enable`
// installs in the Enforced profile (SR-4.14-1). It is separate from the
// base table `inet smcp` of packaging/linux/nftables/smcp.nft, so loading
// either one never removes the other.
const HostRulesTable = "smcp_remote"

// HostRulePorts are the TCP ports of the CP-02 harness listener, the CP-03
// control API listener, the CP-48 remote listener and the CP-51 metrics
// endpoint, from their configured loopback addresses, sorted and without
// duplicates. Empty or unparsable addresses are skipped.
func HostRulePorts(addrs ...string) []int {
	seen := map[int]bool{}
	var out []int
	for _, a := range addrs {
		_, p, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// HostRules is the nftables ruleset of SR-4.14-1: every TCP connection to
// the Gateway's listener ports that does not arrive on the loopback
// interface is dropped. It opens nothing: the chain's only accept is for
// loopback, and the policy (accept) leaves every other port to the host's
// own firewall. Loading it replaces the table atomically.
func HostRules(ports []int) string {
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = strconv.Itoa(p)
	}
	return fmt.Sprintf(`table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname "lo" accept
		tcp dport { %[2]s } counter drop comment "SR-4.14-1: Gateway listeners are reached only through loopback"
	}
}
`, HostRulesTable, strings.Join(ps, ", "))
}

// NFT runs the nft command, located through $SMCP_NFT or the PATH (tests
// substitute a fake). Prefix, when set, is run in front of it (for example
// "ip netns exec <name>").
type NFT struct {
	Bin    string
	Prefix []string
}

// NewNFT locates nft.
func NewNFT() NFT { return NFT{Bin: bin("SMCP_NFT", "nft")} }

func (n NFT) run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	argv := append(append(append([]string{}, n.Prefix...), n.Bin), args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // nft (or its configured stand-in) with fixed arguments
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", filepath.Base(n.Bin), strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Install checks the ruleset with `nft -c -f -`, then loads it with
// `nft -f -`.
func (n NFT) Install(ctx context.Context, ports []int) error {
	if len(ports) == 0 {
		return fmt.Errorf("nftables host rules: no listener ports")
	}
	rules := HostRules(ports)
	if _, err := n.run(ctx, rules, "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nftables host rules rejected: %w", err)
	}
	if _, err := n.run(ctx, rules, "-f", "-"); err != nil {
		return fmt.Errorf("nftables host rules not loaded: %w", err)
	}
	return nil
}

// Remove deletes the table; a table that is not there is not an error.
func (n NFT) Remove(ctx context.Context) error {
	if _, err := n.run(ctx, "", "list", "table", "inet", HostRulesTable); err != nil {
		return nil //nolint:nilerr // nothing installed
	}
	_, err := n.run(ctx, "", "delete", "table", "inet", HostRulesTable)
	return err
}

// List returns the installed table, or an error when it is not installed.
func (n NFT) List(ctx context.Context) (string, error) {
	out, err := n.run(ctx, "", "list", "table", "inet", HostRulesTable)
	return string(out), err
}
