package egress

import (
	"net/netip"
	"slices"
)

// Address classes refused unless a grant names the exact address
// (SR-5.15-2).
const (
	AddrPublic    = "public"
	AddrLoopback  = "loopback"
	AddrPrivate   = "private"
	AddrLinkLocal = "link-local"
	AddrCGNAT     = "cgnat"
	AddrMulticast = "multicast"
	AddrReserved  = "reserved"
	AddrMetadata  = "cloud-metadata"
)

type prefixClass struct {
	p     netip.Prefix
	class string
}

func mustPrefixes(class string, ps ...string) []prefixClass {
	out := make([]prefixClass, 0, len(ps))
	for _, p := range ps {
		out = append(out, prefixClass{netip.MustParsePrefix(p), class})
	}
	return out
}

// metadataAddrs are the instance-metadata services of the common clouds.
// They are checked before the range they fall in so evidence names them.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, OpenStack, DigitalOcean, Oracle
	netip.MustParseAddr("169.254.170.2"),   // AWS ECS task metadata
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	netip.MustParseAddr("192.0.0.192"),     // Oracle Cloud (legacy)
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6
	netip.MustParseAddr("fd20:ce::254"),    // GCP IPv6
}

// classTable is consulted in order; the first matching prefix decides.
// IPv4 per the IANA special-purpose registry (RFC 6890 and updates),
// IPv6 likewise; IPv6 outside 2000::/3 is reserved in any case.
var classTable = slices.Concat(
	mustPrefixes(AddrLoopback, "127.0.0.0/8", "::1/128"),
	mustPrefixes(AddrPrivate, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"),
	mustPrefixes(AddrLinkLocal, "169.254.0.0/16", "fe80::/10"),
	mustPrefixes(AddrCGNAT, "100.64.0.0/10"),
	mustPrefixes(AddrMulticast, "224.0.0.0/4", "ff00::/8"),
	mustPrefixes(AddrReserved,
		"0.0.0.0/8",       // this network
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.88.99.0/24",  // 6to4 relay anycast
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved, includes limited broadcast
		"::/96",           // unspecified and IPv4-compatible
		"64:ff9b:1::/48",  // local-use IPv4/IPv6 translation
		"100::/64",        // discard-only
		"2001::/23",       // IETF protocol assignments, includes Teredo
		"2001:db8::/32",   // documentation
		"3fff::/20",       // documentation
		"5f00::/16",       // SRv6 SIDs
		"fec0::/10",       // deprecated site-local
	),
)

var (
	nat64   = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4  = netip.MustParsePrefix("2002::/16")
	global6 = netip.MustParsePrefix("2000::/3")
)

// Classify returns the address class of ip. Embedded IPv4 addresses of
// IPv4-mapped, NAT64 (64:ff9b::/96) and 6to4 (2002::/16) forms are
// classified as the IPv4 address they carry, so a private address cannot
// be reached through a translation prefix.
func Classify(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Zone() != "" {
		return AddrLinkLocal
	}
	if ip.Is6() {
		b := ip.As16()
		switch {
		case nat64.Contains(ip):
			// Well-known-prefix NAT64 carries the IPv4 destination.
			return Classify(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		case sixTo4.Contains(ip):
			v4 := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
			if c := Classify(v4); c != AddrPublic {
				return c
			}
		}
	}
	if slices.Contains(metadataAddrs, ip) {
		return AddrMetadata
	}
	for _, pc := range classTable {
		if pc.p.Contains(ip) {
			return pc.class
		}
	}
	if ip.Is6() && !global6.Contains(ip) {
		return AddrReserved
	}
	return AddrPublic
}

// permitted reports whether the broker may connect to ip under grant g:
// public addresses always, any other class only when the grant names the
// exact address.
func permitted(ip netip.Addr, g Grant) (bool, string) {
	ip = ip.Unmap()
	class := Classify(ip)
	if class == AddrPublic {
		return true, class
	}
	return slices.Contains(g.Addresses, ip), class
}
