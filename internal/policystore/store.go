// Package policystore is the Policy Store (D-01) of the Policy
// Administration Service (E-05): signed, immutable policy revisions and the
// signed policy-control record that names the active one.
//
// Layout under the state directory:
//
//	keys/policy.key            Ed25519 policy-signing key (hex seed, 0600)
//	keys/policy.pub            its public key (hex, 0644)
//	policy/revisions/<d>.json  one signed revision; <d> is the SHA-256 of
//	                           the canonical document; files are read-only
//	policy/active.json         signed policy-control record (active pointer)
//
// A revision file holds the FR-3.4 record, the canonical document and an
// Ed25519 signature over the record, which carries the document digest
// (SR-1.1-2). Published revisions are never rewritten: Put refuses a second
// document under a used revision ID, and files are created exclusively and
// made read-only (SR-1.14-1). Activation writes the control record to a
// temporary file, flushes it, renames it over active.json and flushes the
// directory before the caller swaps the decision snapshot (SR-1.15-1).
//
// Every read verifies: the file name matches the document digest, the
// signature verifies under the store key, and the document compiles. A
// failure is ErrIntegrity, and the Gateway starts fail-closed with cause
// policy_signature.
package policystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// Paths under the state directory.
const (
	KeyFile      = "keys/policy.key"
	PubFile      = "keys/policy.pub"
	RevisionsDir = "policy/revisions"
	ControlFile  = "policy/active.json"
)

// Signature domains.
const (
	revisionFormat = "smcp-policy-revision/1"
	controlFormat  = "smcp-policy-control/1"
)

// Errors.
var (
	// ErrNoActive: the store has no control record yet (first start).
	ErrNoActive = errors.New("policy store has no active revision")
	// ErrIntegrity: a stored file does not verify.
	ErrIntegrity = errors.New("policy store integrity check failed")
	// ErrInvalidDocument wraps an integrity failure whose signature
	// verified but whose document no longer passes the schema and
	// cross-reference checks (SR-7.3-1).
	ErrInvalidDocument = errors.New("signed revision document is invalid")
	// ErrRevisionExists: the revision ID is already published with other content.
	ErrRevisionExists = errors.New("revision ID already published with different content")
	// ErrNotFound: no published revision has this ID.
	ErrNotFound = errors.New("no such revision")
)

// Record is the FR-3.4 revision record.
type Record struct {
	Revision         string `json:"revision"`
	Sequence         int    `json:"sequence"`
	Parent           string `json:"parent,omitempty"`
	Digest           string `json:"digest"`
	SchemaVersion    string `json:"schema_version"`
	EvaluatorVersion string `json:"evaluator_version"`
	Actor            string `json:"actor"`
	PublishedAt      string `json:"published_at"`
	SimulationRef    string `json:"simulation_ref,omitempty"`
	KeyID            string `json:"key_id"`
	// Origin is how the revision entered the store: import (the policy file
	// at first start), reload (the policy file through policy reload),
	// publish or rollback.
	Origin     string `json:"origin"`
	RollbackOf string `json:"rollback_of,omitempty"`
}

type envelope struct {
	Format    string          `json:"format"`
	Record    Record          `json:"record"`
	Document  json.RawMessage `json:"document"`
	Signature string          `json:"signature"`
}

// Control is the policy-control record: the active revision.
type Control struct {
	Revision    string `json:"revision"`
	Digest      string `json:"digest"`
	Sequence    int    `json:"sequence"`
	Actor       string `json:"actor"`
	ActivatedAt string `json:"activated_at"`
	KeyID       string `json:"key_id"`
	Signature   string `json:"signature,omitempty"`
}

// Revision is a verified stored revision.
type Revision struct {
	Record   Record
	Snapshot *policy.Snapshot
}

// Meta is what the publisher supplies with a document.
type Meta struct {
	Parent        string
	Actor         string
	SimulationRef string
	Origin        string
	RollbackOf    string
}

// Store is an opened Policy Store.
type Store struct {
	state string
	key   ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
	now   func() time.Time

	mu      sync.Mutex
	byID    map[string]Record // revision ID -> record (verified)
	seq     int
	ctlSq   int
	damaged []string
	checked checkedFile // last revision file CheckActive verified
}

// Damaged lists revision files that failed verification when the store was
// opened. They are excluded from List and Get.
func (s *Store) Damaged() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.damaged...)
}

// Open opens the store under stateDir, creating the directories and the
// policy-signing key on first use, and indexes the stored revisions. A
// revision file that does not verify fails Open with ErrIntegrity.
func Open(stateDir string) (*Store, error) {
	for _, d := range []string{filepath.Join(stateDir, "keys"), filepath.Join(stateDir, RevisionsDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	key, err := loadOrCreateKey(stateDir)
	if err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)
	s := &Store{state: stateDir, key: key, pub: pub, keyID: KeyID(pub), now: time.Now, byID: map[string]Record{}}
	if err := s.index(); err != nil {
		return nil, err
	}
	return s, nil
}

// KeyID names a policy-signing key: the first 16 hex digits of the SHA-256
// of the public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// KeyID returns the store's signing key ID.
func (s *Store) KeyID() string { return s.keyID }

// SetNow replaces the clock (tests).
func (s *Store) SetNow(f func() time.Time) { s.now = f }

func loadOrCreateKey(stateDir string) (ed25519.PrivateKey, error) {
	kp := filepath.Join(stateDir, KeyFile)
	b, err := os.ReadFile(kp)
	if errors.Is(err, fs.ErrNotExist) {
		pub, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		f, cerr := os.OpenFile(kp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if cerr != nil {
			return nil, cerr
		}
		_, werr := f.WriteString(hex.EncodeToString(priv.Seed()) + "\n")
		serr := f.Sync()
		if err := errors.Join(werr, serr, f.Close()); err != nil {
			return nil, err
		}
		if err := writeAtomic(filepath.Join(stateDir, PubFile), []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
			return nil, err
		}
		return priv, nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("policy key file is not a 32-byte hex seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return policy.Canonical(raw)
}

func (s *Store) signingBytes(domain string, v any) ([]byte, error) {
	c, err := canonicalJSON(v)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain+"\n"), c...), nil
}

func (s *Store) revPath(digest string) string {
	return filepath.Join(s.state, RevisionsDir, digest+".json")
}

// index reads every revision file and verifies it.
func (s *Store) index() error {
	entries, err := os.ReadDir(filepath.Join(s.state, RevisionsDir))
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		rev, err := s.readFile(strings.TrimSuffix(name, ".json"))
		if errors.Is(err, ErrIntegrity) {
			// Keep going: the active revision is verified on its own, and
			// a damaged historical file must not hide the others.
			s.damaged = append(s.damaged, err.Error())
			continue
		}
		if err != nil {
			return err
		}
		if prev, dup := s.byID[rev.Record.Revision]; dup {
			s.damaged = append(s.damaged, fmt.Sprintf("%v: revision %s is stored twice (%s, %s)", ErrIntegrity, rev.Record.Revision, prev.Digest, rev.Record.Digest))
			continue
		}
		s.byID[rev.Record.Revision] = rev.Record
		if rev.Record.Sequence > s.seq {
			s.seq = rev.Record.Sequence
		}
	}
	return nil
}

// readFile loads and verifies the revision stored under digest.
func (s *Store) readFile(digest string) (*Revision, error) {
	raw, err := os.ReadFile(s.revPath(digest))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: revision file %s.json is missing", ErrIntegrity, digest)
		}
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Format != revisionFormat {
		return nil, fmt.Errorf("%w: %s.json is not a revision file", ErrIntegrity, digest)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	msg, merr := s.signingBytes(revisionFormat, env.Record)
	if err != nil || merr != nil || !ed25519.Verify(s.pub, msg, sig) {
		return nil, fmt.Errorf("%w: %s.json signature does not verify under key %s", ErrIntegrity, digest, s.keyID)
	}
	snap, err := policy.Compile(env.Document)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %s.json: %w", ErrIntegrity, ErrInvalidDocument, digest, err)
	}
	if snap.Digest != env.Record.Digest || snap.Digest != digest || snap.Revision != env.Record.Revision {
		return nil, fmt.Errorf("%w: %s.json content does not match its record", ErrIntegrity, digest)
	}
	return &Revision{Record: env.Record, Snapshot: snap}, nil
}

// Get returns the verified revision with the given ID.
func (s *Store) Get(revision string) (*Revision, error) {
	s.mu.Lock()
	rec, ok := s.byID[revision]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, revision)
	}
	return s.readFile(rec.Digest)
}

// List returns every revision record, newest first.
func (s *Store) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence > out[j].Sequence })
	return out
}

// Put validates, signs and stores a document as a new revision. Storing the
// same content under the same ID again returns the existing revision with
// created false; other content under a used ID is ErrRevisionExists.
func (s *Store) Put(raw []byte, m Meta) (*Revision, bool, error) {
	snap, err := policy.Compile(raw)
	if err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.byID[snap.Revision]; ok {
		if prev.Digest != snap.Digest {
			return nil, false, fmt.Errorf("%w: %s", ErrRevisionExists, snap.Revision)
		}
		return &Revision{Record: prev, Snapshot: snap}, false, nil
	}
	if m.Origin == "" {
		m.Origin = "publish"
	}
	rec := Record{Revision: snap.Revision, Sequence: s.seq + 1, Parent: m.Parent, Digest: snap.Digest,
		SchemaVersion: policy.SchemaVersion, EvaluatorVersion: policy.EvaluatorVersion, Actor: m.Actor,
		PublishedAt: s.now().UTC().Format(time.RFC3339Nano), SimulationRef: m.SimulationRef, KeyID: s.keyID,
		Origin: m.Origin, RollbackOf: m.RollbackOf}
	msg, err := s.signingBytes(revisionFormat, rec)
	if err != nil {
		return nil, false, err
	}
	env := envelope{Format: revisionFormat, Record: rec, Document: snap.Raw, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, msg))}
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, false, err
	}
	if err := writeImmutable(s.revPath(snap.Digest), append(body, '\n')); err != nil {
		return nil, false, err
	}
	s.byID[rec.Revision] = rec
	s.seq = rec.Sequence
	return &Revision{Record: rec, Snapshot: snap}, true, nil
}

// writeImmutable creates path exclusively with the data, flushes it, makes
// it read-only and flushes the directory.
func writeImmutable(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rev-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	if err := errors.Join(werr, serr, tmp.Close()); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return err
	}
	// Link refuses an existing target, so a published file is never replaced.
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s already exists", ErrRevisionExists, filepath.Base(path))
		}
		return err
	}
	return syncDir(filepath.Dir(path))
}

// readControl reads the control record and verifies its signature.
func (s *Store) readControl() (Control, error) {
	raw, err := os.ReadFile(filepath.Join(s.state, ControlFile))
	if errors.Is(err, fs.ErrNotExist) {
		return Control{}, ErrNoActive
	}
	if err != nil {
		return Control{}, err
	}
	var c Control
	if err := json.Unmarshal(raw, &c); err != nil {
		return Control{}, fmt.Errorf("%w: active.json is not a control record", ErrIntegrity)
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	unsigned := c
	unsigned.Signature = ""
	msg, merr := s.signingBytes(controlFormat, unsigned)
	if err != nil || merr != nil || !ed25519.Verify(s.pub, msg, sig) {
		return Control{}, fmt.Errorf("%w: active.json signature does not verify under key %s", ErrIntegrity, s.keyID)
	}
	return c, nil
}

// ErrNotCurrent: the control record names a revision other than the one
// the caller has in force.
var ErrNotCurrent = errors.New("the decision snapshot in force is not the active revision")

// CheckActive verifies that the signed control record names revision and
// that the revision file it points to verifies (FR-7.11 decision-snapshot
// currency). The revision file is re-verified only when its size or
// modification time changed since the last successful check, so the check
// is cheap enough to run every second.
func (s *Store) CheckActive(revision string) error {
	c, err := s.readControl()
	if err != nil {
		return err
	}
	if c.Revision != revision {
		return fmt.Errorf("%w: active.json names %s, %s is in force", ErrNotCurrent, c.Revision, revision)
	}
	fi, err := os.Stat(s.revPath(c.Digest))
	if err != nil {
		return fmt.Errorf("%w: revision file %s.json: %w", ErrIntegrity, c.Digest, err)
	}
	key := checkedFile{digest: c.Digest, size: fi.Size(), mod: fi.ModTime()}
	s.mu.Lock()
	same := s.checked == key
	s.mu.Unlock()
	if same {
		return nil
	}
	rev, err := s.readFile(c.Digest)
	if err != nil {
		return err
	}
	if rev.Record.Revision != c.Revision {
		return fmt.Errorf("%w: active.json names %s but %s.json holds %s", ErrIntegrity, c.Revision, c.Digest, rev.Record.Revision)
	}
	s.mu.Lock()
	s.checked = key
	s.mu.Unlock()
	return nil
}

type checkedFile struct {
	digest string
	size   int64
	mod    time.Time
}

// Active returns the verified active revision and its control record.
func (s *Store) Active() (*Revision, Control, error) {
	c, err := s.readControl()
	if err != nil {
		return nil, Control{}, err
	}
	rev, err := s.readFile(c.Digest)
	if err != nil {
		return nil, Control{}, err
	}
	if rev.Record.Revision != c.Revision {
		return nil, Control{}, fmt.Errorf("%w: active.json names %s but %s.json holds %s", ErrIntegrity, c.Revision, c.Digest, rev.Record.Revision)
	}
	s.mu.Lock()
	if c.Sequence > s.ctlSq {
		s.ctlSq = c.Sequence
	}
	s.mu.Unlock()
	return rev, c, nil
}

// Activate makes rev the active revision: the signed control record is
// written to a temporary file, flushed, renamed over active.json and the
// directory is flushed before Activate returns (SR-1.15-1). It returns the
// record written.
func (s *Store) Activate(rev *Revision, actor string) (Control, error) {
	s.mu.Lock()
	s.ctlSq++
	c := Control{Revision: rev.Record.Revision, Digest: rev.Record.Digest, Sequence: s.ctlSq, Actor: actor,
		ActivatedAt: s.now().UTC().Format(time.RFC3339Nano), KeyID: s.keyID}
	s.mu.Unlock()
	return c, s.writeControl(c)
}

// Restore rewrites a previous control record (used when activation fails
// after the pointer moved). A zero record removes the pointer.
func (s *Store) Restore(c Control) error {
	if c.Revision == "" {
		err := os.Remove(filepath.Join(s.state, ControlFile))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	s.mu.Lock()
	s.ctlSq++
	c.Sequence = s.ctlSq
	s.mu.Unlock()
	c.Signature = ""
	return s.writeControl(c)
}

func (s *Store) writeControl(c Control) error {
	c.Signature = ""
	msg, err := s.signingBytes(controlFormat, c)
	if err != nil {
		return err
	}
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, msg))
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.state, ControlFile), append(body, '\n'), 0o600)
}

// writeAtomic: temporary file, flush, rename, directory flush.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(data)
	cherr := tmp.Chmod(mode)
	serr := tmp.Sync()
	if err := errors.Join(werr, cherr, serr, tmp.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Export returns the canonical JSON document of a revision (FR-3.8).
func (s *Store) Export(revision string) ([]byte, error) {
	rev, err := s.Get(revision)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(rev.Snapshot.Raw), nil
}
