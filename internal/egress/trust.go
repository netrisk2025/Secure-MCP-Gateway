package egress

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// destinationTrust builds the broker's resolver and destination trust
// store from [egress] resolvers and ca_file. With no resolvers the host's
// resolver is used; with no ca_file the system trust store. The
// certificates of ca_file are added to the system trust store.
func destinationTrust(e config.Egress) (Resolver, *x509.CertPool, error) {
	var res Resolver
	if len(e.Resolvers) > 0 {
		res = dnsServers(e.Resolvers)
	}
	if e.CAFile == "" {
		return res, nil, nil
	}
	pem, err := os.ReadFile(e.CAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("egress.ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, nil, errors.New("egress.ca_file: no PEM certificate found")
	}
	return res, pool, nil
}

// dnsServers is a resolver that asks only the listed DNS servers
// (host:port), in turn, over UDP or TCP as the Go resolver chooses.
func dnsServers(servers []string) *net.Resolver {
	var next atomic.Uint64
	n := uint64(len(servers))
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		addr := servers[(next.Add(1)-1)%n]
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
}
