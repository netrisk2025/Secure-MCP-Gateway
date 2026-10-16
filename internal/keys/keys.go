// Package keys is the slice of the Key & Trust Anchor Manager (E-22) this
// prototype needs: a local server CA with a certificate for the harness
// listener (FR-7.7), the Ed25519 evidence-signing key (FR-7.8) and Argon2id
// password hashing (CP-28). Keys are files with mode 0600 under the state
// directory; TPM sealing and passphrase encryption (FR-7.9) are not yet
// implemented.
package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Layout under the state directory.
const (
	CACertFile       = "tls/ca.crt"
	CAKeyFile        = "tls/ca.key"
	ServerCertFile   = "tls/server.crt"
	ServerKeyFile    = "tls/server.key"
	EvidenceKeyFile  = "keys/evidence.key"
	EvidencePubFile  = "keys/evidence.pub"
	EvidenceKeyBytes = ed25519.SeedSize
)

// Ensure creates any missing key material under stateDir for the listener
// host and returns nothing on success. Existing files are kept.
func Ensure(stateDir, listenerHost string) error {
	for _, d := range []string{"tls", "keys"} {
		if err := os.MkdirAll(filepath.Join(stateDir, d), 0o700); err != nil {
			return err
		}
	}
	if !exists(filepath.Join(stateDir, CAKeyFile)) || !exists(filepath.Join(stateDir, ServerKeyFile)) {
		if err := generateTLS(stateDir, listenerHost); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}
	if !exists(filepath.Join(stateDir, EvidenceKeyFile)) {
		if err := generateEvidenceKey(stateDir); err != nil {
			return fmt.Errorf("evidence key: %w", err)
		}
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func generateTLS(stateDir, host string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Secure MCP Gateway server CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "Secure MCP Gateway harness listener"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		srvTmpl.IPAddresses = []net.IP{ip}
	} else {
		srvTmpl.DNSNames = []string{host}
	}
	if host == "127.0.0.1" || host == "localhost" {
		srvTmpl.DNSNames = append(srvTmpl.DNSNames, "localhost")
		srvTmpl.IPAddresses = append(srvTmpl.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(stateDir, CACertFile), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(stateDir, CAKeyFile), "EC PRIVATE KEY", caKeyDER, 0o600); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(stateDir, ServerCertFile), "CERTIFICATE", srvDER, 0o644); err != nil {
		return err
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return err
	}
	return writePEM(filepath.Join(stateDir, ServerKeyFile), "EC PRIVATE KEY", srvKeyDER, 0o600)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func generateEvidenceKey(stateDir string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := hex.EncodeToString(priv.Seed())
	if err := os.WriteFile(filepath.Join(stateDir, EvidenceKeyFile), []byte(seed+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, EvidencePubFile), []byte(hex.EncodeToString(pub)+"\n"), 0o644)
}

// LoadEvidenceKey returns the Ed25519 signing key from the state directory.
func LoadEvidenceKey(stateDir string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, EvidenceKeyFile))
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("evidence key file is not a 32-byte hex seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadEvidencePublicKey returns the verification key from the state directory.
func LoadEvidencePublicKey(stateDir string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, EvidencePubFile))
	if err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("evidence public key file is not a 32-byte hex key")
	}
	return ed25519.PublicKey(pub), nil
}
