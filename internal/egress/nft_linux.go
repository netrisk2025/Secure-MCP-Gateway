//go:build linux

package egress

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TableName is the nftables table the broker owns in each sandbox
// namespace.
const TableName = "smcp_egress"

// NFTables installs the confinement rules with nftables over netlink in
// the sandbox's own network namespace:
//
//	table inet smcp_egress {
//	  chain output { type filter hook output priority 0; policy drop;
//	    oifname "lo" accept
//	    ct state established,related accept
//	    ip daddr <broker> tcp dport <port> accept     (one per listener)
//	    reject with icmpx admin-prohibited }
//	  chain input { type filter hook input priority 0; policy drop;
//	    iifname "lo" accept
//	    ct state established,related accept }
//	}
//
// Everything the instance sends goes nowhere except to its broker
// listeners, including DNS: the broker resolves names (SR-5.15-1).
type NFTables struct{}

func defaultRules() RuleInstaller { return NFTables{} }

// Install implements RuleInstaller.
func (NFTables) Install(netns string, allow []netip.AddrPort) (func() error, error) {
	conn, done, err := nftConn(netns)
	if err != nil {
		return nil, err
	}
	defer done()
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	conn.FlushTable(table)
	drop := nftables.ChainPolicyDrop
	out := conn.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	in := conn.AddChain(&nftables.Chain{Name: "input", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	for _, c := range []struct {
		chain *nftables.Chain
		key   expr.MetaKey
	}{{out, expr.MetaKeyOIFNAME}, {in, expr.MetaKeyIIFNAME}} {
		conn.AddRule(&nftables.Rule{Table: table, Chain: c.chain, Exprs: []expr.Any{
			&expr.Meta{Key: c.key, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
			accept,
		}})
		conn.AddRule(&nftables.Rule{Table: table, Chain: c.chain, Exprs: []expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:  binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			accept,
		}})
	}
	for _, ap := range allow {
		a := ap.Addr().Unmap()
		proto, off, ln := byte(unix.NFPROTO_IPV4), uint32(16), uint32(4)
		if a.Is6() {
			proto, off, ln = byte(unix.NFPROTO_IPV6), 24, 16
		}
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, ap.Port())
		conn.AddRule(&nftables.Rule{Table: table, Chain: out, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: ln},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a.AsSlice()},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
			accept,
		}})
	}
	conn.AddRule(&nftables.Rule{Table: table, Chain: out, Exprs: []expr.Any{
		&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
	}})
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("nftables: %w", err)
	}
	return func() error { return removeTable(netns) }, nil
}

func removeTable(netns string) error {
	conn, done, err := nftConn(netns)
	if err != nil {
		// The namespace is gone with its instance, and its rules with it.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer done()
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	if err := conn.Flush(); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("nftables: remove %s: %w", TableName, err)
	}
	return nil
}

func nftConn(netns string) (*nftables.Conn, func(), error) {
	f, err := os.Open(netns)
	if err != nil {
		return nil, nil, err
	}
	conn, err := nftables.New(nftables.WithNetNSFd(int(f.Fd()))) // #nosec G115 -- a file descriptor fits in int
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return conn, func() { f.Close() }, nil
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}
