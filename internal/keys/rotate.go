package keys

// Key and certificate rotation (FR-17.7) and the key inventory behind
// `smcpctl keys status`.
//
// Listener certificate: RotateLeaf reissues it from the active CA. The
// listeners load the certificate through CertReloader, which picks up the
// new file for new TLS connections; established connections and sessions
// (bearer tokens, not TLS state) continue.
//
// Server CA, with an overlap period: BeginCARotation creates the next CA
// and publishes the trust bundle tls/ca.crt with both CAs (active first).
// During the overlap the listeners keep presenting the certificate issued
// by the outgoing CA, so clients that trust only the outgoing CA connect,
// and clients that have already imported the bundle trust both. When the
// overlap ends (FinishCARotation, called by the operations runtime when
// switch_at passes or by `smcpctl keys rotate ca --finish`), the next CA
// becomes active, the listener certificate is reissued from it and the
// outgoing CA is moved to tls/retired/. Clients that never imported the new
// CA stop connecting at that point.
//
// Evidence-signing key: StagePendingEvidenceKey stores the incoming key as
// keys/evidence.key.next; the journal then writes the key-transition record
// (audit.Journal.RotateKey) and CommitPendingEvidenceKey makes the incoming
// key current. A crash between the steps is resolved at the next start by
// ResolvePendingEvidenceKey, which compares the pending key with the
// journal's last transition record.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Files used by rotation.
const (
	CANextCertFile         = "tls/ca-next.crt"
	CANextKeyFile          = "tls/ca-next.key"
	CARotationFile         = "tls/rotation.json"
	CARetiredDir           = "tls/retired"
	EvidencePendingKeyFile = "keys/evidence.key.next"
)

// DefaultCAOverlap is the overlap used when the operator names none.
const DefaultCAOverlap = 7 * 24 * time.Hour

// CARotation is the state of a server CA rotation in progress.
type CARotation struct {
	Stage     string    `json:"stage"` // "overlap"
	StartedAt time.Time `json:"started_at"`
	SwitchAt  time.Time `json:"switch_at"`
	NextCA    CertInfo  `json:"next_ca"`
}

// CertInfo describes one certificate.
type CertInfo struct {
	Subject     string    `json:"subject"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SHA256      string    `json:"sha256"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	IPAddresses []string  `json:"ip_addresses,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
}

func certInfo(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.Raw)
	ci := CertInfo{Subject: c.Subject.String(), Serial: c.SerialNumber.Text(16), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(),
		SHA256: hex.EncodeToString(sum[:]), DNSNames: c.DNSNames}
	if !c.IsCA {
		ci.Issuer = c.Issuer.String()
	}
	for _, ip := range c.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	return ci
}

// loadBundle returns every certificate in a PEM file, in order.
func loadBundle(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no certificate", path)
	}
	return out, nil
}

func writeBundle(path string, certs ...*x509.Certificate) error {
	var buf bytes.Buffer
	for _, c := range certs {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	return WriteFileAtomic(path, buf.Bytes(), 0o644)
}

// rotMu serializes rotations within one process.
var rotMu sync.Mutex

// RotateLeaf reissues the listener certificate from the active CA now,
// whatever its remaining validity (`smcpctl keys rotate tls`).
func RotateLeaf(stateDir string, names ...string) (TLSStatus, error) {
	rotMu.Lock()
	defer rotMu.Unlock()
	return rotateLeafLocked(stateDir, time.Now(), names)
}

func rotateLeafLocked(stateDir string, now time.Time, names []string) (TLSStatus, error) {
	var st TLSStatus
	caCert, err := loadCert(filepath.Join(stateDir, CACertFile))
	if err != nil {
		return st, err
	}
	if !now.Before(caCert.NotAfter) {
		return st, errors.New("server CA has expired; rotate it with `smcpctl keys rotate ca --overlap 0`")
	}
	caKey, err := loadECKey(filepath.Join(stateDir, CAKeyFile))
	if err != nil {
		return st, err
	}
	dns, ips := leafNames(names)
	dns, ips, st.Uncovered = splitPermitted(caCert, dns, ips)
	if err := issueLeaf(stateDir, caCert, caKey, dns, ips); err != nil {
		return st, err
	}
	leaf, err := loadCert(filepath.Join(stateDir, ServerCertFile))
	if err != nil {
		return st, err
	}
	st.CANotAfter, st.LeafNotAfter, st.LeafRotated = caCert.NotAfter, leaf.NotAfter, true
	st.CADue = now.Add(RotateBefore).After(caCert.NotAfter)
	return st, nil
}

// LoadCARotation returns the CA rotation in progress, or nil.
func LoadCARotation(stateDir string) (*CARotation, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, CARotationFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var r CARotation
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", CARotationFile, err)
	}
	return &r, nil
}

// ErrRotationInProgress is returned when a CA rotation is already in its
// overlap period.
var ErrRotationInProgress = errors.New("a server CA rotation is already in its overlap period; finish it first (smcpctl keys rotate ca --finish)")

// BeginCARotation creates the next server CA and publishes the trust bundle
// with both CAs. With overlap zero it finishes at once. names are the
// listener names the new CA's constraints must permit.
func BeginCARotation(stateDir string, now time.Time, overlap time.Duration, names ...string) (*CARotation, TLSStatus, error) {
	rotMu.Lock()
	defer rotMu.Unlock()
	if cur, err := LoadCARotation(stateDir); err != nil {
		return nil, TLSStatus{}, err
	} else if cur != nil {
		return cur, TLSStatus{}, ErrRotationInProgress
	}
	if overlap < 0 {
		return nil, TLSStatus{}, errors.New("overlap must not be negative")
	}
	active, err := loadBundle(filepath.Join(stateDir, CACertFile))
	if err != nil {
		return nil, TLSStatus{}, err
	}
	// The overlap cannot outlast the outgoing CA: its leaf is presented
	// until the switch.
	if until := time.Until(active[0].NotAfter) - time.Hour; overlap > until && until > 0 {
		overlap = until
	}
	next, _, nextDER, nextKeyDER, err := newCA(now, names)
	if err != nil {
		return nil, TLSStatus{}, err
	}
	if err := writePEM(filepath.Join(stateDir, CANextKeyFile), "EC PRIVATE KEY", nextKeyDER, 0o600); err != nil {
		return nil, TLSStatus{}, err
	}
	if err := writePEM(filepath.Join(stateDir, CANextCertFile), "CERTIFICATE", nextDER, 0o644); err != nil {
		return nil, TLSStatus{}, err
	}
	if err := writeBundle(filepath.Join(stateDir, CACertFile), active[0], next); err != nil {
		return nil, TLSStatus{}, err
	}
	rot := &CARotation{Stage: "overlap", StartedAt: now.UTC(), SwitchAt: now.Add(overlap).UTC(), NextCA: certInfo(next)}
	b, err := json.MarshalIndent(rot, "", "  ")
	if err != nil {
		return nil, TLSStatus{}, err
	}
	if err := WriteFileAtomic(filepath.Join(stateDir, CARotationFile), append(b, '\n'), 0o600); err != nil {
		return nil, TLSStatus{}, err
	}
	if overlap == 0 {
		st, err := finishCALocked(stateDir, now, names)
		return rot, st, err
	}
	// Names that only the new CA permits wait for the switch; the current
	// leaf stays as it is.
	st, err := RotateIfDue(stateDir, now, names...)
	return rot, st, err
}

// FinishCARotation makes the next CA active, reissues the listener
// certificate from it and retires the outgoing CA.
func FinishCARotation(stateDir string, now time.Time, names ...string) (TLSStatus, error) {
	rotMu.Lock()
	defer rotMu.Unlock()
	return finishCALocked(stateDir, now, names)
}

func finishCALocked(stateDir string, now time.Time, names []string) (TLSStatus, error) {
	rot, err := LoadCARotation(stateDir)
	if err != nil {
		return TLSStatus{}, err
	}
	if rot == nil {
		return TLSStatus{}, errors.New("no server CA rotation is in progress")
	}
	next, err := loadCert(filepath.Join(stateDir, CANextCertFile))
	if err != nil {
		return TLSStatus{}, err
	}
	nextKey, err := os.ReadFile(filepath.Join(stateDir, CANextKeyFile))
	if err != nil {
		return TLSStatus{}, err
	}
	old, err := loadBundle(filepath.Join(stateDir, CACertFile))
	if err != nil {
		return TLSStatus{}, err
	}
	if err := os.MkdirAll(filepath.Join(stateDir, CARetiredDir), 0o700); err != nil {
		return TLSStatus{}, err
	}
	retired := filepath.Join(stateDir, CARetiredDir, "ca-"+old[0].SerialNumber.Text(16)+".crt")
	if err := writeBundle(retired, old[0]); err != nil {
		return TLSStatus{}, err
	}
	// Order: key first, then the bundle with the new CA first, so a crash
	// leaves either the old pair or the new pair usable with the next files
	// still present to retry.
	if err := WriteFileAtomic(filepath.Join(stateDir, CAKeyFile), nextKey, 0o600); err != nil {
		return TLSStatus{}, err
	}
	if err := writeBundle(filepath.Join(stateDir, CACertFile), next); err != nil {
		return TLSStatus{}, err
	}
	st, err := rotateLeafLocked(stateDir, now, names)
	if err != nil {
		return st, err
	}
	for _, f := range []string{CANextCertFile, CANextKeyFile, CARotationFile} {
		if err := os.Remove(filepath.Join(stateDir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return st, err
		}
	}
	return st, nil
}

// AdvanceCARotation finishes a CA rotation whose overlap has ended. It
// reports whether it switched.
func AdvanceCARotation(stateDir string, now time.Time, names ...string) (bool, TLSStatus, error) {
	rot, err := LoadCARotation(stateDir)
	if err != nil || rot == nil || now.Before(rot.SwitchAt) {
		return false, TLSStatus{}, err
	}
	st, err := FinishCARotation(stateDir, now, names...)
	return err == nil, st, err
}

// NewEvidenceKey generates an Ed25519 evidence-signing key.
func NewEvidenceKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// StagePendingEvidenceKey stores the incoming evidence key before the
// journal writes the transition record, and records the trust root when it
// was not recorded yet.
func StagePendingEvidenceKey(stateDir string, next ed25519.PrivateKey) error {
	if err := ensureGenesis(stateDir); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(stateDir, EvidencePendingKeyFile), []byte(hex.EncodeToString(next.Seed())+"\n"), 0o600)
}

// ensureGenesis writes evidence-genesis.pub from evidence.pub when missing:
// installations made before key rotation existed have only the one key,
// which is the genesis key.
func ensureGenesis(stateDir string) error {
	g := filepath.Join(stateDir, EvidenceGenesisFile)
	if exists(g) {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(stateDir, EvidencePubFile))
	if err != nil {
		return err
	}
	return WriteFileAtomic(g, b, 0o644)
}

// CommitPendingEvidenceKey makes the staged key the current evidence key.
func CommitPendingEvidenceKey(stateDir string) error {
	next, err := loadSeed(filepath.Join(stateDir, EvidencePendingKeyFile))
	if err != nil {
		return err
	}
	pub := next.Public().(ed25519.PublicKey)
	if err := WriteFileAtomic(filepath.Join(stateDir, EvidenceKeyFile), []byte(hex.EncodeToString(next.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	if err := WriteFileAtomic(filepath.Join(stateDir, EvidencePubFile), []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Remove(filepath.Join(stateDir, EvidencePendingKeyFile))
}

// ResolvePendingEvidenceKey finishes or discards an interrupted evidence-key
// rotation. lastNextKey is the next_key of the journal's last closed
// segment ("" when it has none). The pending key is committed when the
// journal already handed over to it, and discarded otherwise. It reports
// what it did: "", "committed" or "discarded".
func ResolvePendingEvidenceKey(stateDir, lastNextKey string) (string, error) {
	p := filepath.Join(stateDir, EvidencePendingKeyFile)
	if !exists(p) {
		return "", nil
	}
	next, err := loadSeed(p)
	if err != nil {
		return "", err
	}
	if lastNextKey != "" && lastNextKey == hex.EncodeToString(next.Public().(ed25519.PublicKey)) {
		return "committed", CommitPendingEvidenceKey(stateDir)
	}
	return "discarded", os.Remove(p)
}

func loadSeed(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a 32-byte hex seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadEvidenceTrustRoot returns the key that signed the first journal
// segment: evidence-genesis.pub when present, else evidence.pub.
func LoadEvidenceTrustRoot(stateDir string) (ed25519.PublicKey, error) {
	p := filepath.Join(stateDir, EvidenceGenesisFile)
	if !exists(p) {
		return LoadEvidencePublicKey(stateDir)
	}
	return ReadPublicKeyFile(p)
}

// ReadPublicKeyFile reads a hex Ed25519 public key file such as
// evidence.pub or evidence-genesis.pub.
func ReadPublicKeyFile(p string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is not a 32-byte hex Ed25519 public key", filepath.Base(p))
	}
	return ed25519.PublicKey(pub), nil
}

// Status is the key inventory reported by `smcpctl keys status`.
type Status struct {
	ServerCA       CertInfo    `json:"server_ca"`
	TrustBundle    []CertInfo  `json:"trust_bundle"`
	Listener       CertInfo    `json:"listener_certificate"`
	CARotation     *CARotation `json:"ca_rotation,omitempty"`
	CADue          bool        `json:"ca_due"`
	ListenerDue    bool        `json:"listener_due"`
	EvidenceKey    string      `json:"evidence_public_key"`
	EvidenceRoot   string      `json:"evidence_trust_root"`
	PendingRotate  bool        `json:"evidence_rotation_pending"`
	InstallationID string      `json:"installation_id,omitempty"`
	// Purposes lists the key purposes of FR-7.8 that exist in this build
	// and the files that hold them.
	Purposes map[string]string `json:"purposes"`
}

// ReadStatus builds the key inventory from the state directory.
func ReadStatus(stateDir string, now time.Time) (Status, error) {
	var s Status
	bundle, err := loadBundle(filepath.Join(stateDir, CACertFile))
	if err != nil {
		return s, err
	}
	s.ServerCA = certInfo(bundle[0])
	for _, c := range bundle {
		s.TrustBundle = append(s.TrustBundle, certInfo(c))
	}
	leaf, err := loadCert(filepath.Join(stateDir, ServerCertFile))
	if err != nil {
		return s, err
	}
	s.Listener = certInfo(leaf)
	s.CADue = now.Add(RotateBefore).After(bundle[0].NotAfter)
	s.ListenerDue = now.Add(RotateBefore).After(leaf.NotAfter)
	if s.CARotation, err = LoadCARotation(stateDir); err != nil {
		return s, err
	}
	if pub, err := LoadEvidencePublicKey(stateDir); err == nil {
		s.EvidenceKey = hex.EncodeToString(pub)
	}
	if pub, err := LoadEvidenceTrustRoot(stateDir); err == nil {
		s.EvidenceRoot = hex.EncodeToString(pub)
	}
	s.PendingRotate = exists(filepath.Join(stateDir, EvidencePendingKeyFile))
	if b, err := os.ReadFile(filepath.Join(stateDir, InstallationIDFile)); err == nil {
		s.InstallationID = strings.TrimSpace(string(b))
	}
	s.Purposes = map[string]string{"server_ca": CAKeyFile, "server_tls": ServerKeyFile, "evidence_signing": EvidenceKeyFile, "operator_token": AdminTokenFile}
	return s, nil
}

// CertReloader serves the listener certificate from its files and reloads
// it when the certificate file changes, so a rotated certificate is used
// for new connections without restarting the listener. The file is checked
// at most once per second.
type CertReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	size    int64
	checked time.Time
}

// NewCertReloader loads the pair once and returns the reloader.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	r := &CertReloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CertReloader) load() error {
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.modTime, r.size = &c, st.ModTime(), st.Size()
	return nil
}

// GetCertificate implements tls.Config.GetCertificate. When a reload fails
// (for example while the key and certificate are being replaced) the
// previous certificate is kept.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := time.Now(); now.Sub(r.checked) >= time.Second {
		r.checked = now
		if st, err := os.Stat(r.certFile); err == nil && (!st.ModTime().Equal(r.modTime) || st.Size() != r.size) {
			_ = r.load()
		}
	}
	return r.cert, nil
}

// Reload forces the next handshake to re-read the files.
func (r *CertReloader) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checked = time.Time{}
	return r.load()
}
