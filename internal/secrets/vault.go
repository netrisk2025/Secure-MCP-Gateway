// Package secrets is the Secret Vault (E-19) and the Secret Broker (E-20).
//
// The vault keeps each secret as a versioned record whose values are
// encrypted with age to the vault master key (SR-2.13-1); the master key
// lives in the macOS Keychain or, wrapped under a passphrase, in
// <vault>/master.age, and never on disk in plaintext. Every read operation
// returns metadata only (FR-6.2). Plaintext leaves the vault only through
// the broker in this package (SR-2.13-3: no exported function returns a
// value).
//
// The broker delivers secrets to server instances in the mode a Secret Use
// Policy selects (S1 header injection through the Egress Broker, S2
// per-call file, S3 per-instance file, S4 launch environment variable with
// a waiver), records every delivery and denial as evidence without the
// value (FR-6.11), and registers keyed leak fingerprints of each delivered
// value (FR-6.10) that the request and response filters of this package
// and other elements scan for.
package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// StoreFile is the vault store under the vault directory.
const StoreFile = "secrets.json"

// MaxValueBytes bounds one secret value.
const MaxValueBytes = 32 << 10

// MaxOverlap is the CP-15 rotation overlap ceiling.
const MaxOverlap = 24 * time.Hour

// Version states.
const (
	StateCurrent = "current"
	StateOverlap = "overlap"
	StateRetired = "retired"
)

// Secret types.
var Types = []string{"api_key", "token", "password", "certificate", "connection_string", "generic"}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Errors returned by the vault. Their texts never contain a value.
var (
	ErrNotFound        = errors.New("secret not found")
	ErrExists          = errors.New("secret already exists")
	ErrExpired         = errors.New("secret expired")
	ErrRetired         = errors.New("secret version retired")
	ErrNoEvidence      = errors.New("vault has no evidence recorder")
	ErrNotInitialized  = errors.New("vault not initialized (run `smcpctl secrets init`)")
	ErrInvalidName     = errors.New("secret name must match ^[a-z0-9][a-z0-9._-]{0,63}$")
	ErrInvalidValue    = fmt.Errorf("secret value must have %d to %d bytes", MinValueBytes, MaxValueBytes)
	ErrInvalidType     = errors.New("secret type must be one of api_key, token, password, certificate, connection_string, generic")
	ErrInvalidOverlap  = errors.New("rotation overlap must be between 0s and 24h (CP-15)")
	ErrPermissionsOpen = errors.New("vault files must be readable by their owner only")
)

type storeFile struct {
	Format    int       `json:"format"`
	VaultID   string    `json:"vault_id"`
	KeySource string    `json:"key_source"`
	Recipient string    `json:"recipient"`
	Created   time.Time `json:"created"`
	Secrets   []*record `json:"secrets"`
}

type record struct {
	Ref         string     `json:"ref"`
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Owner       string     `json:"owner"`
	Description string     `json:"description,omitempty"`
	Created     time.Time  `json:"created"`
	Rotated     *time.Time `json:"rotated,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	Current     int        `json:"current_version"`
	Versions    []*version `json:"versions"`
}

type version struct {
	Version          int        `json:"version"`
	Created          time.Time  `json:"created"`
	State            string     `json:"state"`
	DeliverableUntil *time.Time `json:"deliverable_until,omitempty"`
	RetiredAt        *time.Time `json:"retired_at,omitempty"`
	// Ciphertext is the age-encrypted value; deleted on retirement
	// (FR-6.4).
	Ciphertext []byte `json:"ciphertext,omitempty"`
}

// Meta is the metadata view of a secret: everything except the value and
// its ciphertext (FR-6.2).
type Meta struct {
	Ref            string        `json:"ref"`
	Name           string        `json:"name"`
	Type           string        `json:"type"`
	Owner          string        `json:"owner"`
	Description    string        `json:"description,omitempty"`
	Created        time.Time     `json:"created"`
	Rotated        *time.Time    `json:"rotated,omitempty"`
	Expires        *time.Time    `json:"expires,omitempty"`
	CurrentVersion int           `json:"current_version"`
	Versions       []VersionMeta `json:"versions"`
}

// VersionMeta is the metadata of one version.
type VersionMeta struct {
	Version          int        `json:"version"`
	Created          time.Time  `json:"created"`
	State            string     `json:"state"`
	DeliverableUntil *time.Time `json:"deliverable_until,omitempty"`
	RetiredAt        *time.Time `json:"retired_at,omitempty"`
}

func (r *record) meta() Meta {
	m := Meta{Ref: r.Ref, Name: r.Name, Type: r.Type, Owner: r.Owner, Description: r.Description, Created: r.Created,
		Rotated: r.Rotated, Expires: r.Expires, CurrentVersion: r.Current, Versions: []VersionMeta{}}
	for _, v := range r.Versions {
		m.Versions = append(m.Versions, VersionMeta{Version: v.Version, Created: v.Created, State: v.State, DeliverableUntil: v.DeliverableUntil, RetiredAt: v.RetiredAt})
	}
	return m
}

// VaultOptions configure an opened vault.
type VaultOptions struct {
	// Overlap is the default rotation overlap (CP-15, at most 24h).
	Overlap time.Duration
	Now     func() time.Time
	// Evidence records vault changes. Mutations fail without it.
	Evidence audit.Recorder
}

// Vault is an unlocked Secret Vault (E-19).
type Vault struct {
	dir      string
	identity *age.X25519Identity
	recip    *age.X25519Recipient
	overlap  time.Duration
	now      func() time.Time

	mu       sync.Mutex
	st       *storeFile
	rec      audit.Recorder
	onRetire []func(ref string, version int)
}

// KeySourceFor returns the key source a vault directory uses.
func KeySourceFor(dir, name string, passphrase func() (string, error)) (KeySource, error) {
	switch name {
	case KeySourceKeychain:
		st, err := readStore(dir)
		account := ""
		if err == nil {
			account = "vault-" + st.VaultID
		}
		return Keychain{Account: account}, nil
	case KeySourcePassphrase:
		return Passphrase{Path: filepath.Join(dir, MasterKeyFile), Passphrase: passphrase}, nil
	}
	return nil, fmt.Errorf("unknown key source %q", name)
}

// Init creates a vault in dir: a new master key held by ks and an empty
// store. It refuses an existing vault. For the Keychain source, Account is
// set from the new vault ID when empty.
func Init(dir string, ks KeySource) (vaultID string, err error) {
	if _, err := os.Stat(filepath.Join(dir, StoreFile)); err == nil {
		return "", errors.New("vault already initialized")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the search bit; owner only
		return "", err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", err
	}
	vaultID = ids.New()
	if kc, ok := ks.(Keychain); ok && kc.Account == "" {
		kc.Account = "vault-" + vaultID
		ks = kc
	}
	if err := ks.Store(id.String()); err != nil {
		return "", err
	}
	st := &storeFile{Format: 1, VaultID: vaultID, KeySource: ks.Name(), Recipient: id.Recipient().String(), Created: time.Now().UTC(), Secrets: []*record{}}
	if err := writeStore(dir, st); err != nil {
		return "", err
	}
	return vaultID, nil
}

// StoreInfo is what can be learned about a vault without unlocking it.
type StoreInfo struct {
	VaultID   string `json:"vault_id"`
	KeySource string `json:"key_source"`
	Recipient string `json:"recipient"`
	Secrets   int    `json:"secrets"`
}

// Inspect reads a vault's store without unlocking it.
func Inspect(dir string) (StoreInfo, error) {
	st, err := readStore(dir)
	if err != nil {
		return StoreInfo{}, err
	}
	return StoreInfo{VaultID: st.VaultID, KeySource: st.KeySource, Recipient: st.Recipient, Secrets: len(st.Secrets)}, nil
}

func readStore(dir string) (*storeFile, error) {
	p := filepath.Join(dir, StoreFile)
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %o", ErrPermissionsOpen, p, fi.Mode().Perm())
	}
	if di, err := os.Stat(dir); err == nil && di.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %o", ErrPermissionsOpen, dir, di.Mode().Perm())
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var st storeFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("vault store: %w", err)
	}
	if st.Format != 1 {
		return nil, fmt.Errorf("vault store format %d not supported", st.Format)
	}
	return &st, nil
}

func writeStore(dir string, st *storeFile) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, StoreFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, StoreFile)); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// Open unlocks the vault in dir with ks.
func Open(dir string, ks KeySource, o VaultOptions) (*Vault, error) {
	st, err := readStore(dir)
	if err != nil {
		return nil, err
	}
	if ks.Name() != st.KeySource {
		return nil, fmt.Errorf("vault was initialized with key source %q, not %q", st.KeySource, ks.Name())
	}
	if kc, ok := ks.(Keychain); ok && kc.Account == "" {
		kc.Account = "vault-" + st.VaultID
		ks = kc
	}
	idStr, err := ks.Load()
	if err != nil {
		return nil, err
	}
	id, err := age.ParseX25519Identity(idStr)
	if err != nil {
		return nil, fmt.Errorf("%w: master key unparseable", ErrLocked)
	}
	if id.Recipient().String() != st.Recipient {
		return nil, fmt.Errorf("%w: master key does not match the vault", ErrLocked)
	}
	if o.Overlap < 0 || o.Overlap > MaxOverlap {
		return nil, ErrInvalidOverlap
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Vault{dir: dir, identity: id, recip: id.Recipient(), overlap: o.Overlap, now: o.Now, st: st, rec: o.Evidence}, nil
}

// Check reports whether the vault is available (FR-7.11): its store file
// can be read with safe permissions and is still the vault this process
// unlocked, so the next create, rotation or removal can be persisted and
// the in-memory versions match the file.
func (v *Vault) Check() error {
	st, err := readStore(v.dir)
	if err != nil {
		return err
	}
	v.mu.Lock()
	id, recip := v.st.VaultID, v.recip.String()
	v.mu.Unlock()
	if st.VaultID != id || st.Recipient != recip {
		return fmt.Errorf("%w: the vault store no longer matches the unlocked key", ErrLocked)
	}
	return nil
}

// SetEvidence sets the recorder of vault changes.
func (v *Vault) SetEvidence(rec audit.Recorder) {
	v.mu.Lock()
	v.rec = rec
	v.mu.Unlock()
}

// OnRetire registers a hook called (without the vault lock) after a version
// is retired.
func (v *Vault) OnRetire(f func(ref string, version int)) {
	v.mu.Lock()
	v.onRetire = append(v.onRetire, f)
	v.mu.Unlock()
}

// ID returns the vault ID.
func (v *Vault) ID() string { v.mu.Lock(); defer v.mu.Unlock(); return v.st.VaultID }

// KeySource returns the name of the vault's key source.
func (v *Vault) KeySource() string { v.mu.Lock(); defer v.mu.Unlock(); return v.st.KeySource }

// DefaultOverlap returns the configured rotation overlap.
func (v *Vault) DefaultOverlap() time.Duration { return v.overlap }

func (v *Vault) find(name string) *record {
	for _, r := range v.st.Secrets {
		if r.Name == name {
			return r
		}
	}
	return nil
}

func (v *Vault) findRef(ref string) *record {
	for _, r := range v.st.Secrets {
		if r.Ref == ref {
			return r
		}
	}
	return nil
}

func (v *Vault) encrypt(value []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, v.recip)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(value); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decrypt returns the plaintext in a buffer the caller must wipe.
func (v *Vault) decrypt(ct []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ct), v.identity)
	if err != nil {
		return nil, errors.New("vault: ciphertext does not decrypt")
	}
	// Read into one buffer sized from the ciphertext so that no growing
	// copies of the plaintext are left behind.
	buf := make([]byte, len(ct))
	n := 0
	for {
		m, err := r.Read(buf[n:])
		n += m
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			wipe(buf)
			return nil, errors.New("vault: ciphertext does not decrypt")
		}
		if n == len(buf) {
			wipe(buf)
			return nil, errors.New("vault: plaintext longer than expected")
		}
	}
	return buf[:n], nil
}

func (v *Vault) commit(ev audit.Event) error {
	if v.rec == nil {
		return ErrNoEvidence
	}
	ev.Class, ev.Origin = "secret", "E-19"
	if ev.PolicyStatus == "" {
		ev.PolicyStatus = "not_evaluated"
	}
	if err := v.rec.Commit(ev); err != nil {
		return fmt.Errorf("evidence unavailable: %w", err)
	}
	return nil
}

// CreateParams describe a new secret. Value is wiped by Create.
type CreateParams struct {
	Name        string
	Type        string
	Owner       string
	Description string
	Expires     *time.Time
	Value       []byte
}

func checkValue(b []byte) error {
	if len(b) < MinValueBytes || len(b) > MaxValueBytes {
		return ErrInvalidValue
	}
	return nil
}

// Create stores a new secret as version 1.
func (v *Vault) Create(actor string, p CreateParams) (Meta, error) {
	defer wipe(p.Value)
	if !namePattern.MatchString(p.Name) {
		return Meta{}, ErrInvalidName
	}
	if p.Type == "" {
		p.Type = "generic"
	}
	if !slices.Contains(Types, p.Type) {
		return Meta{}, ErrInvalidType
	}
	if err := checkValue(p.Value); err != nil {
		return Meta{}, err
	}
	if p.Owner == "" {
		p.Owner = actor
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.rec == nil {
		return Meta{}, ErrNoEvidence
	}
	if v.find(p.Name) != nil {
		return Meta{}, ErrExists
	}
	ct, err := v.encrypt(p.Value)
	if err != nil {
		return Meta{}, err
	}
	now := v.now().UTC()
	r := &record{Ref: "sec_" + ids.New(), Name: p.Name, Type: p.Type, Owner: p.Owner, Description: p.Description, Created: now, Expires: p.Expires,
		Current: 1, Versions: []*version{{Version: 1, Created: now, State: StateCurrent, Ciphertext: ct}}}
	v.st.Secrets = append(v.st.Secrets, r)
	if err := writeStore(v.dir, v.st); err != nil {
		v.st.Secrets = v.st.Secrets[:len(v.st.Secrets)-1]
		return Meta{}, err
	}
	if err := v.commit(audit.Event{Outcome: "created", Detail: map[string]any{"secret_ref": r.Ref, "name": r.Name, "type": r.Type, "version": 1, "actor": actor}}); err != nil {
		return Meta{}, err
	}
	return r.meta(), nil
}

// Rotate stores value as a new current version. The previous current
// version stays deliverable for overlap (at most CP-15) and is then
// retired; a negative overlap selects the configured default.
func (v *Vault) Rotate(actor, name string, value []byte, overlap time.Duration) (Meta, error) {
	defer wipe(value)
	if overlap < 0 {
		overlap = v.overlap
	}
	if overlap > MaxOverlap {
		return Meta{}, ErrInvalidOverlap
	}
	if err := checkValue(value); err != nil {
		return Meta{}, err
	}
	var retired []int
	v.mu.Lock()
	if v.rec == nil {
		v.mu.Unlock()
		return Meta{}, ErrNoEvidence
	}
	r := v.find(name)
	if r == nil {
		v.mu.Unlock()
		return Meta{}, ErrNotFound
	}
	ct, err := v.encrypt(value)
	if err != nil {
		v.mu.Unlock()
		return Meta{}, err
	}
	now := v.now().UTC()
	prev := r.Current
	until := now.Add(overlap)
	for _, ver := range r.Versions {
		if ver.Version == prev {
			if overlap == 0 {
				retire(ver, now)
				retired = append(retired, ver.Version)
			} else {
				ver.State, ver.DeliverableUntil = StateOverlap, &until
			}
		} else if ver.State == StateOverlap {
			// Only one previous version overlaps at a time.
			retire(ver, now)
			retired = append(retired, ver.Version)
		}
	}
	next := r.Versions[len(r.Versions)-1].Version + 1
	r.Versions = append(r.Versions, &version{Version: next, Created: now, State: StateCurrent, Ciphertext: ct})
	r.Current, r.Rotated = next, &now
	if err := writeStore(v.dir, v.st); err != nil {
		v.mu.Unlock()
		return Meta{}, err
	}
	detail := map[string]any{"secret_ref": r.Ref, "name": r.Name, "version": next, "previous_version": prev, "actor": actor}
	if overlap > 0 {
		detail["previous_deliverable_until"] = until
	}
	err = v.commit(audit.Event{Outcome: "rotated", Detail: detail})
	for _, n := range retired {
		if e := v.commit(audit.Event{Outcome: "retired", ReasonCode: "SECRET_RETIRED", Detail: map[string]any{"secret_ref": r.Ref, "name": r.Name, "version": n, "reason": "rotated"}}); err == nil {
			err = e
		}
	}
	m, ref, hooks := r.meta(), r.Ref, slices.Clone(v.onRetire)
	v.mu.Unlock()
	for _, n := range retired {
		for _, h := range hooks {
			h(ref, n)
		}
	}
	return m, err
}

func retire(ver *version, now time.Time) {
	wipe(ver.Ciphertext)
	ver.Ciphertext = nil
	ver.State, ver.RetiredAt, ver.DeliverableUntil = StateRetired, &now, nil
}

// Remove retires every version of a secret and deletes its record.
func (v *Vault) Remove(actor, name string) error {
	v.mu.Lock()
	if v.rec == nil {
		v.mu.Unlock()
		return ErrNoEvidence
	}
	i := slices.IndexFunc(v.st.Secrets, func(r *record) bool { return r.Name == name })
	if i < 0 {
		v.mu.Unlock()
		return ErrNotFound
	}
	r := v.st.Secrets[i]
	now := v.now().UTC()
	var retired []int
	for _, ver := range r.Versions {
		if ver.State != StateRetired {
			retire(ver, now)
			retired = append(retired, ver.Version)
		}
	}
	v.st.Secrets = slices.Delete(v.st.Secrets, i, i+1)
	if err := writeStore(v.dir, v.st); err != nil {
		v.mu.Unlock()
		return err
	}
	var err error
	for _, n := range retired {
		if e := v.commit(audit.Event{Outcome: "retired", ReasonCode: "SECRET_RETIRED", Detail: map[string]any{"secret_ref": r.Ref, "name": r.Name, "version": n, "reason": "removed"}}); err == nil {
			err = e
		}
	}
	if e := v.commit(audit.Event{Outcome: "removed", Detail: map[string]any{"secret_ref": r.Ref, "name": r.Name, "actor": actor}}); err == nil {
		err = e
	}
	hooks := slices.Clone(v.onRetire)
	v.mu.Unlock()
	for _, n := range retired {
		for _, h := range hooks {
			h(r.Ref, n)
		}
	}
	return err
}

// Sweep retires overlap versions whose deliverable period has ended
// (FR-6.3, FR-6.4). It returns the number retired.
func (v *Vault) Sweep() (int, error) {
	type ret struct {
		ref, name string
		n         int
	}
	var done []ret
	v.mu.Lock()
	now := v.now().UTC()
	for _, r := range v.st.Secrets {
		for _, ver := range r.Versions {
			if ver.State == StateOverlap && ver.DeliverableUntil != nil && !now.Before(*ver.DeliverableUntil) {
				retire(ver, now)
				done = append(done, ret{r.Ref, r.Name, ver.Version})
			}
		}
	}
	if len(done) == 0 {
		v.mu.Unlock()
		return 0, nil
	}
	if err := writeStore(v.dir, v.st); err != nil {
		v.mu.Unlock()
		return 0, err
	}
	var err error
	for _, d := range done {
		if e := v.commit(audit.Event{Outcome: "retired", ReasonCode: "SECRET_RETIRED", Detail: map[string]any{"secret_ref": d.ref, "name": d.name, "version": d.n, "reason": "overlap_elapsed"}}); err == nil {
			err = e
		}
	}
	hooks := slices.Clone(v.onRetire)
	v.mu.Unlock()
	for _, d := range done {
		for _, h := range hooks {
			h(d.ref, d.n)
		}
	}
	return len(done), err
}

// List returns the metadata of every secret, by name.
func (v *Vault) List() []Meta {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Meta, 0, len(v.st.Secrets))
	for _, r := range v.st.Secrets {
		out = append(out, r.meta())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the metadata of one secret.
func (v *Vault) Get(name string) (Meta, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	r := v.find(name)
	if r == nil {
		return Meta{}, ErrNotFound
	}
	return r.meta(), nil
}

// opened is a decrypted value handed to the broker. Value must be wiped.
type opened struct {
	Ref     string
	Name    string
	Version int
	Value   []byte
}

// open decrypts a deliverable version of a secret: the current version
// when version is 0, else the named version while it is current or within
// its overlap. Only the broker calls it (SR-2.13-3).
func (v *Vault) open(name string, version int) (opened, error) {
	v.mu.Lock()
	r := v.find(name)
	if r == nil {
		v.mu.Unlock()
		return opened{}, ErrNotFound
	}
	now := v.now()
	if r.Expires != nil && !now.Before(*r.Expires) {
		v.mu.Unlock()
		return opened{Ref: r.Ref, Name: r.Name}, ErrExpired
	}
	if version == 0 {
		version = r.Current
	}
	var ct []byte
	for _, ver := range r.Versions {
		if ver.Version != version {
			continue
		}
		deliverable := ver.State == StateCurrent || (ver.State == StateOverlap && ver.DeliverableUntil != nil && now.Before(*ver.DeliverableUntil))
		if deliverable {
			ct = slices.Clone(ver.Ciphertext)
		}
	}
	ref := r.Ref
	v.mu.Unlock()
	if ct == nil {
		return opened{Ref: ref, Name: name, Version: version}, ErrRetired
	}
	pt, err := v.decrypt(ct)
	if err != nil {
		return opened{Ref: ref, Name: name, Version: version}, err
	}
	return opened{Ref: ref, Name: name, Version: version, Value: pt}, nil
}

// nameOfRef returns the name of a secret reference.
func (v *Vault) nameOfRef(ref string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if r := v.findRef(ref); r != nil {
		return r.Name
	}
	return ""
}
