package sandbox

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Egress for sandboxed servers (E-16 with E-18, SR-4.5-1).
//
// An instance whose runtime.server entry sets network = "egress" runs on a
// slirp4netns network with host loopback enabled, so that it can reach
// the Egress Broker's listeners on 127.0.0.1 at the guest address
// 10.0.2.2. Before the server's code runs, the launcher installs an
// nftables table in the container's network namespace that drops every
// packet except TCP to the broker listeners of this instance:
//
//  1. podman create (the launch specification, network slirp4netns)
//  2. podman init (network namespace and mounts exist, process not started)
//  3. podman unshare nsenter --net=<namespace> nft -f -   (EgressRules)
//  4. podman unshare nsenter --net=<namespace> nft list table ...  (check)
//  5. podman start --attach --interactive
//
// Step 3 runs in the rootless user namespace that owns the network
// namespace, which is the only place an unprivileged Gateway holds
// CAP_NET_ADMIN over it. The instance itself has every capability
// dropped, so it cannot change the table. Any failure removes the
// container and closes the broker attachment: the launch fails closed.
const EgressNetworkMode = "slirp4netns:allow_host_loopback=true"

// EgressTable is the nftables table the launcher installs in an egress
// instance's network namespace.
const EgressTable = "smcp_egress"

var (
	// egressListenAddr is where the broker binds the instance's listeners.
	egressListenAddr = netip.MustParseAddr("127.0.0.1")
	// egressGuestAddr is how the instance reaches egressListenAddr through
	// slirp4netns (allow_host_loopback).
	egressGuestAddr = netip.MustParseAddr("10.0.2.2")
)

// EgressRules returns the nftables script that confines a namespace to the
// listed endpoints:
//
//	table inet smcp_egress {
//	  chain output { type filter hook output priority filter; policy drop;
//	    oifname "lo" accept
//	    ct state established,related accept
//	    ip daddr <addr> tcp dport <port> accept      (one per endpoint)
//	    reject with icmpx admin-prohibited }
//	  chain input { type filter hook input priority filter; policy drop;
//	    iifname "lo" accept
//	    ct state established,related accept }
//	}
//
// Nothing else leaves the namespace, DNS included: the broker resolves
// names (SR-5.15-1).
func EgressRules(allow []netip.AddrPort) (string, error) {
	var b strings.Builder
	b.WriteString("table inet " + EgressTable + " {\n")
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n")
	b.WriteString("\t\toifname \"lo\" accept\n\t\tct state established,related accept\n")
	for _, ap := range allow {
		a := ap.Addr().Unmap()
		if !a.IsValid() || ap.Port() == 0 {
			return "", fmt.Errorf("invalid egress endpoint %q", ap)
		}
		fam := "ip"
		if a.Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "\t\t%s daddr %s tcp dport %d accept\n", fam, a, ap.Port())
	}
	b.WriteString("\t\treject with icmpx admin-prohibited\n\t}\n")
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n")
	b.WriteString("\t\tiifname \"lo\" accept\n\t\tct state established,related accept\n\t}\n}\n")
	return b.String(), nil
}

// hostTool returns the absolute path of a host tool, looking in PATH and
// then in the system directories a service PATH may lack.
func hostTool(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		if a, err := filepath.Abs(p); err == nil {
			return a
		}
	}
	for _, d := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return name
}

// createPrepared creates and initializes the container of an instance
// that must be prepared before its process starts: with egress, its
// network namespace is confined to allow (the namespace path is returned);
// with secretDir, the instance's host UID is granted its secret files
// (secretacl.go). On failure the container is removed.
func (l *Launcher) createPrepared(ls LaunchSpec, values map[string]string, egress bool, allow []netip.AddrPort, secretDir string) (netns string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	defer func() {
		if err != nil {
			rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer rcancel()
			_ = l.podman(rctx, "rm", "--force", "--time", "0", ls.Name).Run()
			if egress {
				err = fmt.Errorf("egress confinement: %w", err)
			}
		}
	}()
	rules := ""
	if egress {
		if rules, err = EgressRules(allow); err != nil {
			return "", err
		}
	}
	if secretDir != "" && l.run.runAs != nil {
		// Podman, running as run_as, resolves the bind-mount source.
		if err := l.grantTraversal(secretDir, l.run.runAs.UID); err != nil {
			return "", err
		}
	}
	create := l.run.command(ctx, values, ls.CreateArgs()...)
	if out, err := create.CombinedOutput(); err != nil {
		return "", fmt.Errorf("podman create: %w: %s", err, bounded(out))
	}
	if out, err := l.podman(ctx, "init", ls.Name).CombinedOutput(); err != nil {
		return "", fmt.Errorf("podman init: %w: %s", err, bounded(out))
	}
	if secretDir != "" {
		if err := l.grantSecretFiles(ctx, ls, secretDir); err != nil {
			return "", err
		}
	}
	if !egress {
		return "", nil
	}
	return l.confineEgress(ctx, ls, rules, allow)
}

// confineEgress installs rules in the created container's network
// namespace and reads them back.
func (l *Launcher) confineEgress(ctx context.Context, ls LaunchSpec, rules string, allow []netip.AddrPort) (string, error) {
	out, err := l.podman(ctx, "inspect", "--type", "container", "--format", "{{.NetworkSettings.SandboxKey}}", ls.Name).Output()
	if err != nil {
		return "", fmt.Errorf("podman inspect: %w", err)
	}
	netns := strings.TrimSpace(string(out))
	if !filepath.IsAbs(netns) {
		return "", fmt.Errorf("container %s has no network namespace path (got %q)", ls.Name, netns)
	}
	nsenter, nft := l.o.Nsenter, l.o.Nft
	if nsenter == "" {
		nsenter = hostTool("nsenter")
	}
	if nft == "" {
		nft = hostTool("nft")
	}
	install := l.podman(ctx, "unshare", nsenter, "--net="+netns, nft, "-f", "-")
	install.Stdin = strings.NewReader(rules)
	if out, err := install.CombinedOutput(); err != nil {
		return "", fmt.Errorf("install the egress rules in %s: %w: %s", netns, err, bounded(out))
	}
	// Read the table back: the instance starts only when the drop policy
	// is in place.
	out, err = l.podman(ctx, "unshare", nsenter, "--net="+netns, nft, "list", "table", "inet", EgressTable).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read back the egress rules in %s: %w: %s", netns, err, bounded(out))
	}
	if !strings.Contains(string(out), "policy drop") {
		return "", errors.New("the egress rules were not installed: no drop policy in table " + EgressTable)
	}
	for _, ap := range allow {
		if !strings.Contains(string(out), "dport "+strconv.Itoa(int(ap.Port()))) {
			return "", fmt.Errorf("the egress rules lack the broker endpoint %s", ap)
		}
	}
	return netns, nil
}

func bounded(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 2048 {
		s = s[:2048] + "..."
	}
	return s
}
