package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// reissueDNSOnlyCA replaces the instance's server CA and listener
// certificate with a CA whose name constraints permit only DNS "localhost"
// (no iPAddress subtrees). It exists for the -dns-only-ca diagnostic: TLS
// stacks built on BoringSSL, such as the Bun runtime of the native Claude
// Code and OpenCode builds, reject the CP-53 iPAddress name constraints with
// "unsupported name constraint type". A run with this option deviates from
// CP-53 and is labelled so in agents.json; it shows whether the CA is the
// only obstacle for a client.
func reissueDNSOnlyCA(stateDir string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	serial := func() *big.Int {
		n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		return n
	}
	ca := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Secure MCP Gateway server CA (conformance suite, DNS-only constraints)"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"localhost"},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Secure MCP Gateway listener"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(89 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return err
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name, typ string
		der       []byte
		mode      os.FileMode
	}{
		{"ca.crt", "CERTIFICATE", caDER, 0o644},
		{"ca.key", "EC PRIVATE KEY", caKeyDER, 0o600},
		{"server.crt", "CERTIFICATE", leafDER, 0o644},
		{"server.key", "EC PRIVATE KEY", leafKeyDER, 0o600},
	} {
		if err := os.WriteFile(filepath.Join(stateDir, "tls", f.name), pem.EncodeToMemory(&pem.Block{Type: f.typ, Bytes: f.der}), f.mode); err != nil {
			return err
		}
	}
	return nil
}
