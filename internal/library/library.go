// Package library is the Library Trust Verifier (E-13) and the Local
// Server Registry (E-14): it imports signed packages from the local
// directory library (FR-5.1, FR-5.2, SR-3-1), stores each verified artifact
// in a content-addressed cache under the state directory (FR-5.39),
// keeps every imported revision immutable with a registry state
// (FR-5.5, FR-5.7), writes import receipts (FR-5.4), processes revocation
// entries (SR-3-3, FR-14.12) and expiry (FR-5.8), and enables a revision
// only on an administrator action (SR-3.9-1), refusing high-risk revisions
// in the Standalone profile (SR-4-1).
//
// At run time it is the verified pipeline.ManifestSource: a [[server]]
// entry that names a package is launched from the enabled revision's
// artifact after the artifact digest is re-verified (SR-3-2); its live
// tools/list is compared with the manifest at start and on every
// notifications/tools/list_changed, and a difference suspends the revision
// and records the evidence (SR-3.8-1).
//
// Single writer: the registry file is guarded by an exclusive lock that
// smcpd holds while it runs; smcpctl takes it for offline changes and
// refuses when the Gateway holds it.
package library

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Registry states (FR-5.7).
const (
	StateVerifiedDisabled = "verified-disabled"
	StateEnabled          = "enabled"
	StateSuspended        = "suspended"
	StateRevoked          = "revoked"
	StateRetired          = "retired"
)

// Reason codes added by the registry; packaging reason codes are reused for
// verification failures.
const (
	ReasonRevoked          = "REVOKED"
	ReasonDowngrade        = "DOWNGRADE_REFUSED"
	ReasonRevisionConflict = "REVISION_CONFLICT"
	ReasonProfile          = "PROFILE_UNCONFINED"
	ReasonAliasConflict    = "ALIAS_CONFLICT"
	ReasonNameCollision    = "PUBLIC_NAME_COLLISION"
	ReasonStateful         = "STATEFUL_UNCONTRACTED"
	ReasonExpired          = "MANIFEST_EXPIRED"
	ReasonState            = "STATE_TRANSITION_REFUSED"
	ReasonUnknown          = "PACKAGE_UNKNOWN"
	ReasonNotEnabled       = "PACKAGE_NOT_ENABLED"
	ReasonPinMismatch      = "PACKAGE_PIN_MISMATCH"
	ReasonDrift            = "MANIFEST_DRIFT"
	ReasonTampered         = "ARTIFACT_TAMPERED"
	ReasonUnsigned         = "UNSIGNED_SERVER_REFUSED"
	ReasonLocked           = "REGISTRY_LOCKED"
)

// Error is a registry refusal with a reason code.
type Error = packaging.Error

func errf(reason, format string, args ...any) *Error { return packaging.Errf(reason, format, args...) }

// ErrLocked is returned by Open when another process holds the registry.
var ErrLocked = errors.New("the package registry is locked by another process (is smcpd running? use the control API)")

// Layout under the state directory.
const (
	packagesDir  = "packages"
	registryFile = "registry.json"
	lockFile     = "registry.lock"
)

// Revision is one imported, immutable server revision (FR-5.5).
type Revision struct {
	ServerID       string    `json:"server_id"`
	Revision       string    `json:"revision"`
	State          string    `json:"state"`
	StateReason    string    `json:"state_reason,omitempty"`
	StateChangedAt time.Time `json:"state_changed_at"`
	StateActor     string    `json:"state_actor,omitempty"`
	Alias          string    `json:"alias"`
	RiskClass      string    `json:"risk_class"`
	ArtifactType   string    `json:"artifact_type"`
	IndexSHA256    string    `json:"index_sha256"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	TreeSHA256     string    `json:"tree_sha256,omitempty"`
	ToolsSHA256    string    `json:"tools_sha256"`
	// EnablementSHA256 binds enablement to the digest of the manifest tool
	// definitions and declared capabilities (SR-3.7-1).
	EnablementSHA256 string    `json:"enablement_sha256,omitempty"`
	SignerKeyID      string    `json:"signer_key_id"`
	Anchor           string    `json:"anchor"`
	ImportedAt       time.Time `json:"imported_at"`
	Expires          string    `json:"expires,omitempty"`
	RecurationDue    string    `json:"recuration_due,omitempty"`
	Tools            []string  `json:"tools"`
	// Overrides are operator classifications that tighten the manifest's
	// (SR-3.11-1), by tool name.
	Overrides map[string]ToolOverride `json:"overrides,omitempty"`
}

// Key is "<server-id>@<revision>".
func (r *Revision) Key() string { return r.ServerID + "@" + r.Revision }

type registryDoc struct {
	Version   int         `json:"version"`
	Revisions []*Revision `json:"revisions"`
	// Revocations already applied, by key.
	Revocations map[string]string `json:"revocations,omitempty"`
}

// Options configure a Library.
type Options struct {
	StateDir string
	// Dir is the directory library scanned for packages (default
	// <state>/library).
	Dir string
	Log *slog.Logger
	Now func() time.Time
}

// Library is the verifier and registry.
type Library struct {
	stateDir string
	dir      string
	log      *slog.Logger
	now      func() time.Time
	lock     *os.File

	mu       sync.Mutex
	doc      registryDoc
	rec      audit.Recorder    // nil offline
	rejected map[string]string // package dir -> rejected index digest
	// feedReadAt is the last successful read of the revocation feed (from
	// the library's opening when it was never read); feedAlerted records
	// that the stale-feed alert was raised for the current stale period
	// (SR-3-4).
	feedReadAt  time.Time
	feedAlerted bool
}

// Open loads the registry and takes the exclusive registry lock.
func Open(o Options) (*Library, error) {
	if o.StateDir == "" {
		return nil, errors.New("library: state directory required")
	}
	if o.Dir == "" {
		o.Dir = filepath.Join(o.StateDir, "library")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	l := &Library{stateDir: o.StateDir, dir: o.Dir, log: o.Log, now: o.Now}
	l.feedReadAt = o.Now()
	for _, d := range []string{l.path(), l.path("artifacts", "sha256"), l.path("unpacked"), l.path("revisions"), l.path("receipts"), l.path("evidence"), l.path("work"), l.dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(l.path(lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // a file descriptor fits in int
		f.Close()
		return nil, ErrLocked
	}
	l.lock = f
	if err := l.load(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Close releases the registry lock.
func (l *Library) Close() error {
	if l.lock == nil {
		return nil
	}
	_ = syscall.Flock(int(l.lock.Fd()), syscall.LOCK_UN) //nolint:gosec // a file descriptor fits in int
	err := l.lock.Close()
	l.lock = nil
	return err
}

// Dir is the directory library.
func (l *Library) Dir() string { return l.dir }

func (l *Library) path(parts ...string) string {
	return filepath.Join(append([]string{l.stateDir, packagesDir}, parts...)...)
}

func (l *Library) load() error {
	raw, err := os.ReadFile(l.path(registryFile))
	if errors.Is(err, os.ErrNotExist) {
		l.doc = registryDoc{Version: 1}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &l.doc); err != nil {
		return fmt.Errorf("package registry: %w", err)
	}
	return nil
}

// save writes the registry; the caller holds mu.
func (l *Library) save() error {
	sort.Slice(l.doc.Revisions, func(i, j int) bool { return l.doc.Revisions[i].Key() < l.doc.Revisions[j].Key() })
	return packaging.WriteJSON(l.path(registryFile), l.doc, 0o600)
}

// SetRecorder makes the library write evidence events (smcpd).
func (l *Library) SetRecorder(rec audit.Recorder) {
	l.mu.Lock()
	l.rec = rec
	l.mu.Unlock()
}

// evidence commits an event when a recorder is set; the caller may hold mu.
func (l *Library) evidence(ev audit.Event) error {
	if l.rec == nil {
		return nil
	}
	ev.Class, ev.PolicyStatus = "package", "not_evaluated"
	if ev.Origin == "" {
		ev.Origin = "E-14"
	}
	return l.rec.Commit(ev)
}

func (l *Library) find(id, rev string) *Revision {
	for _, r := range l.doc.Revisions {
		if r.ServerID == id && r.Revision == rev {
			return r
		}
	}
	return nil
}

// Revisions returns a copy of every revision.
func (l *Library) Revisions() []Revision {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Revision, 0, len(l.doc.Revisions))
	for _, r := range l.doc.Revisions {
		out = append(out, *r)
	}
	return out
}

// Get returns one revision.
func (l *Library) Get(id, rev string) (Revision, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.find(id, rev); r != nil {
		return *r, true
	}
	return Revision{}, false
}

// revisionDir holds the immutable copy of a revision's signed metadata.
func (l *Library) revisionDir(id, rev string) string { return l.path("revisions", id, rev) }

// Manifest loads a revision's manifest from its immutable copy.
func (l *Library) Manifest(id, rev string) (*packaging.Manifest, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(l.revisionDir(id, rev), packaging.ManifestFile))
	if err != nil {
		return nil, nil, err
	}
	m, err := packaging.ParseManifest(raw)
	return m, raw, err
}

// ArtifactPath is the content-addressed artifact file.
func (l *Library) ArtifactPath(sha string) string { return l.path("artifacts", "sha256", sha) }

// TreePath is the unpacked artifact tree.
func (l *Library) TreePath(sha string) string { return l.path("unpacked", sha) }

// compareRevision orders revisions by their dot-separated components,
// numerically where both are numbers (SR-3-5).
func compareRevision(a, b string) int {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '_' })
	}
	pa, pb := split(strings.TrimPrefix(a, "v")), split(strings.TrimPrefix(b, "v"))
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.ParseUint(pa[i], 10, 64)
		nb, eb := strconv.ParseUint(pb[i], 10, 64)
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		default:
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
		}
	}
	return len(pa) - len(pb)
}

// setState changes a revision's state; the caller holds mu.
func (l *Library) setState(r *Revision, state, reason, actor string) {
	r.State, r.StateReason, r.StateActor, r.StateChangedAt = state, reason, actor, l.now().UTC()
}

// transitions lists the allowed state changes (FR-5.7).
var transitions = map[string][]string{
	StateVerifiedDisabled: {StateEnabled, StateRetired, StateRevoked},
	StateEnabled:          {StateVerifiedDisabled, StateSuspended, StateRetired, StateRevoked},
	StateSuspended:        {StateEnabled, StateVerifiedDisabled, StateRetired, StateRevoked},
	StateRevoked:          {},
	StateRetired:          {},
}

func allowed(from, to string) bool { return slices.Contains(transitions[from], to) }
