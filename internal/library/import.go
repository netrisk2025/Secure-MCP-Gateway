package library

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Receipt is the import receipt written for every import attempt (FR-5.4).
type Receipt struct {
	ReceiptVersion int      `json:"receipt_version"`
	Time           string   `json:"time"`
	Actor          string   `json:"actor"`
	PackageDir     string   `json:"package_dir"`
	ServerID       string   `json:"server_id,omitempty"`
	Revision       string   `json:"revision,omitempty"`
	IndexSHA256    string   `json:"index_sha256,omitempty"`
	ArtifactSHA256 string   `json:"artifact_sha256,omitempty"`
	ManifestSHA256 string   `json:"manifest_sha256,omitempty"`
	SignerKeyID    string   `json:"signer_key_id,omitempty"`
	Anchor         string   `json:"anchor,omitempty"`
	Result         string   `json:"result"` // accepted, rejected, unchanged
	ReasonCode     string   `json:"reason_code,omitempty"`
	Error          string   `json:"error,omitempty"`
	Checks         []string `json:"checks"`
	File           string   `json:"-"`
}

// ImportOptions configure Import.
type ImportOptions struct {
	Actor string
	// AllowDowngrade is the administrator's authorization to import a
	// revision lower than an installed one (SR-3-5).
	AllowDowngrade bool
}

// verifyChecks are the checks a successful packaging.Verify performed, in
// order; a receipt lists them.
var verifyChecks = []string{"components", "signature", "anchor_expiry", "digests", "manifest_schema", "provenance_binding", "anchor_scope"}

// Import verifies a package directory and registers it as a new
// verified-disabled revision (FR-5.2, SR-3-1, FR-5.5). A receipt is written
// for every attempt, accepted or not.
func (l *Library) Import(dir string, o ImportOptions) (*Receipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.importLocked(dir, o)
}

func (l *Library) importLocked(dir string, o ImportOptions) (*Receipt, error) {
	if o.Actor == "" {
		o.Actor = "operator"
	}
	rc := &Receipt{ReceiptVersion: 1, Time: l.now().UTC().Format(time.RFC3339Nano), Actor: o.Actor, PackageDir: dir, Checks: []string{}}
	var err error
	// SR-3-4: no import while the revocation feed is stale.
	if stale, why := l.feedStaleLocked(); stale {
		err = errf(ReasonFeedStale, "%s", why)
	} else {
		err = l.doImport(dir, o, rc)
	}
	if err != nil {
		rc.Result, rc.ReasonCode, rc.Error = "rejected", packaging.ReasonOf(err), err.Error()
		if rc.ReasonCode == "" {
			rc.ReasonCode = "IMPORT_FAILED"
		}
	}
	if werr := l.writeReceipt(rc); werr != nil && err == nil {
		err = werr
	}
	outcome := map[string]string{"accepted": "imported", "rejected": "import_rejected", "unchanged": "import_unchanged"}[rc.Result]
	if eerr := l.evidence(audit.Event{Origin: "E-13", Outcome: outcome, ReasonCode: rc.ReasonCode, ServerRevision: rc.ServerID + "@" + rc.Revision,
		Detail: map[string]any{"receipt": filepath.Base(rc.File), "actor": rc.Actor, "artifact_sha256": rc.ArtifactSHA256, "signer_key_id": rc.SignerKeyID, "anchor": rc.Anchor}}); eerr != nil && err == nil {
		err = eerr
	}
	return rc, err
}

func (l *Library) writeReceipt(rc *Receipt) error {
	name := strings.NewReplacer(":", "", ".", "").Replace(rc.Time)
	id := rc.ServerID
	if id == "" {
		id = "unknown"
	}
	rc.File = l.path("receipts", fmt.Sprintf("%s-%s@%s-%s.json", name, id, rc.Revision, rc.Result))
	return packaging.WriteJSON(rc.File, rc, 0o600)
}

func (l *Library) doImport(dir string, o ImportOptions, rc *Receipt) error {
	anchors, err := packaging.LoadAnchors(l.stateDir)
	if err != nil {
		return err
	}
	// Identify the package for the receipt even when verification fails.
	if raw, err := os.ReadFile(filepath.Join(dir, packaging.IndexFile)); err == nil {
		var ix packaging.Index
		if json.Unmarshal(raw, &ix) == nil {
			rc.ServerID, rc.Revision, rc.SignerKeyID = ix.ServerID, ix.Revision, ix.SignerKeyID
			rc.IndexSHA256, rc.ArtifactSHA256 = packaging.SHA256Hex(raw), ix.Artifact.SHA256
		}
	}
	pkg, err := packaging.Verify(dir, packaging.VerifyOptions{Keys: anchors.Resolver(), Now: l.now()})
	if err != nil {
		return err
	}
	rc.Checks = append(rc.Checks, verifyChecks...)
	m, ix := pkg.Manifest, pkg.Index
	rc.ManifestSHA256 = ix.Manifest.SHA256
	if id, err := packaging.ParseKeyID(ix.SignerKeyID); err == nil {
		if _, an, err := anchors.Resolver()(id); err == nil && an != nil {
			rc.Anchor = an.Name
		}
	}
	key := ix.ServerID + "@" + ix.Revision
	if _, revoked := l.doc.Revocations[key]; revoked {
		return errf(ReasonRevoked, "%s has been revoked", key)
	}
	rc.Checks = append(rc.Checks, "revocation")
	if ex := l.find(ix.ServerID, ix.Revision); ex != nil {
		if ex.IndexSHA256 == rc.IndexSHA256 {
			rc.Result = "unchanged"
			return nil
		}
		return errf(ReasonRevisionConflict, "%s is already imported with a different package index; revisions are immutable", key)
	}
	if !o.AllowDowngrade {
		for _, r := range l.doc.Revisions {
			if r.ServerID == ix.ServerID && r.State != StateRetired && compareRevision(ix.Revision, r.Revision) < 0 {
				return errf(ReasonDowngrade, "%s is lower than the installed revision %s; an administrator must authorize the downgrade", key, r.Revision)
			}
		}
	}
	rc.Checks = append(rc.Checks, "rollback")
	tree, err := l.store(pkg)
	if err != nil {
		return err
	}
	rc.Checks = append(rc.Checks, "artifact_stored")
	// Immutable copy of the signed metadata.
	rdir := l.revisionDir(ix.ServerID, ix.Revision)
	if err := os.MkdirAll(rdir, 0o700); err != nil {
		return err
	}
	for _, f := range []string{packaging.IndexFile, packaging.SignatureFile, packaging.ManifestFile, packaging.ProvenanceFile} {
		src := filepath.Join(dir, f)
		if f == packaging.ManifestFile {
			src = filepath.Join(dir, filepath.FromSlash(ix.Manifest.Path))
		} else if f == packaging.ProvenanceFile {
			src = filepath.Join(dir, filepath.FromSlash(ix.Provenance.Path))
		}
		_ = os.Remove(filepath.Join(rdir, f))
		if err := packaging.CopyFile(src, filepath.Join(rdir, f), 0o400); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(m.Tools))
	for _, t := range m.Tools {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	r := &Revision{ServerID: ix.ServerID, Revision: ix.Revision, Alias: m.Server.Alias, RiskClass: m.HighestRisk(), ArtifactType: m.Artifact.Type,
		IndexSHA256: rc.IndexSHA256, ManifestSHA256: ix.Manifest.SHA256, ArtifactSHA256: ix.Artifact.SHA256, TreeSHA256: tree,
		ToolsSHA256: m.ToolsListSHA256, SignerKeyID: ix.SignerKeyID, Anchor: rc.Anchor, ImportedAt: l.now().UTC(), Expires: m.Expires, Tools: names}
	if m.Attestations != nil {
		r.RecurationDue = m.Attestations.RecurationDue
	}
	l.setState(r, StateVerifiedDisabled, "imported", o.Actor)
	l.doc.Revisions = append(l.doc.Revisions, r)
	if err := l.save(); err != nil {
		return err
	}
	rc.Result = "accepted"
	return nil
}

// store puts the artifact into the content-addressed cache (FR-5.39) and
// unpacks archive artifacts; it returns the tree digest ("" for OCI).
func (l *Library) store(p *packaging.Package) (string, error) {
	sum := p.Index.Artifact.SHA256
	dst := l.ArtifactPath(sum)
	if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
		tmp := dst + ".tmp"
		_ = os.Remove(tmp)
		if err := packaging.CopyFile(p.ArtifactPath(), tmp, 0o444); err != nil {
			return "", err
		}
		if got, _, err := packaging.FileSHA256(tmp); err != nil || got != sum {
			os.Remove(tmp)
			return "", errf(packaging.ReasonDigestMismatch, "artifact changed while it was stored")
		}
		if err := os.Rename(tmp, dst); err != nil {
			return "", err
		}
	}
	if p.Manifest.Artifact.Type == "oci" {
		return "", nil
	}
	tree := l.TreePath(sum)
	if _, err := os.Stat(tree); err == nil {
		return packaging.TreeDigest(tree)
	}
	if err := l.unpack(sum, p.Manifest.Artifact.Type, filepath.Base(p.Index.Artifact.Path)); err != nil {
		return "", err
	}
	return packaging.TreeDigest(tree)
}

// unpack writes the unpacked tree of a stored archive or binary artifact.
func (l *Library) unpack(sum, typ, binName string) error {
	tree := l.TreePath(sum)
	tmp := tree + ".tmp"
	packaging.MakeWritable(tmp)
	_ = os.RemoveAll(tmp)
	switch typ {
	case "binary":
		if err := os.Mkdir(tmp, 0o755); err != nil {
			return err
		}
		if err := packaging.CopyFile(l.ArtifactPath(sum), filepath.Join(tmp, binName), 0o555); err != nil {
			return err
		}
	default:
		if err := packaging.ExtractTarGz(l.ArtifactPath(sum), tmp, ""); err != nil {
			packaging.MakeWritable(tmp)
			os.RemoveAll(tmp)
			return fmt.Errorf("unpack artifact: %w", err)
		}
	}
	return os.Rename(tmp, tree)
}

// ensureTree re-creates a missing unpacked tree from the content-addressed
// artifact after checking its digest. The tree is a cache of the artifact
// (backups leave it out); the launch check still compares it with the tree
// digest recorded at import (SR-3-2), so an altered tree is still refused.
func (l *Library) ensureTree(rev Revision) error {
	if rev.ArtifactType == "oci" || rev.TreeSHA256 == "" {
		return nil
	}
	if _, err := os.Stat(l.TreePath(rev.ArtifactSHA256)); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	sum, _, err := packaging.FileSHA256(l.ArtifactPath(rev.ArtifactSHA256))
	if err != nil {
		return errf(ReasonTampered, "artifact %s unreadable: %v", rev.ArtifactSHA256, err)
	}
	if sum != rev.ArtifactSHA256 {
		return errf(ReasonTampered, "artifact digest is %s, the signed manifest names %s", sum, rev.ArtifactSHA256)
	}
	raw, err := os.ReadFile(filepath.Join(l.revisionDir(rev.ServerID, rev.Revision), packaging.IndexFile))
	if err != nil {
		return err
	}
	var ix packaging.Index
	if err := json.Unmarshal(raw, &ix); err != nil {
		return fmt.Errorf("revision index: %w", err)
	}
	l.log.Info("re-creating the unpacked artifact tree from the stored artifact", "revision", rev.Key())
	return l.unpack(rev.ArtifactSHA256, rev.ArtifactType, filepath.Base(ix.Artifact.Path))
}

// ScanReport summarizes one library scan (FR-5.3).
type ScanReport struct {
	Imported  []string `json:"imported"`
	Rejected  []string `json:"rejected"`
	Revoked   []string `json:"revoked"`
	Suspended []string `json:"suspended"`
	Errors    []string `json:"errors"`
}

// packageDirs lists directories under the library holding an index.json,
// at depth one (<lib>/<pkg>) or two (<lib>/<id>/<rev>).
func (l *Library) packageDirs() []string {
	var out []string
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || e.Name() == packaging.RevocationsDir || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			p := filepath.Join(d, e.Name())
			if _, err := os.Stat(filepath.Join(p, packaging.IndexFile)); err == nil {
				out = append(out, p)
			} else if depth < 2 {
				walk(p, depth+1)
			}
		}
	}
	walk(l.dir, 1)
	sort.Strings(out)
	return out
}

// Scan imports new packages from the library, applies revocation entries
// (SR-3-3, FR-14.12) and suspends expired revisions (FR-5.8). It returns
// the aliases whose enabled revision left the enabled state, so the caller
// can tear their instances down.
func (l *Library) Scan(actor string) (ScanReport, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rep := ScanReport{Imported: []string{}, Rejected: []string{}, Revoked: []string{}, Suspended: []string{}, Errors: []string{}}
	known := map[string]string{}
	for _, r := range l.doc.Revisions {
		known[r.Key()] = r.IndexSHA256
	}
	for _, d := range l.packageDirs() {
		raw, err := os.ReadFile(filepath.Join(d, packaging.IndexFile))
		if err != nil {
			continue
		}
		var ix packaging.Index
		_ = json.Unmarshal(raw, &ix)
		if sha, ok := known[ix.ServerID+"@"+ix.Revision]; ok && sha == packaging.SHA256Hex(raw) {
			continue // already imported, unchanged
		}
		if l.rejectedBefore(d, packaging.SHA256Hex(raw)) {
			continue
		}
		rc, err := l.importLocked(d, ImportOptions{Actor: actor})
		switch {
		case err != nil:
			rep.Rejected = append(rep.Rejected, fmt.Sprintf("%s: %v", d, err))
			// A missing component may be a copy still in progress: retry it
			// on the next scan. Other rejections are final for this index.
			if !strings.HasSuffix(packaging.ReasonOf(err), "_MISSING") {
				l.markRejected(d, packaging.SHA256Hex(raw))
			}
		case rc.Result == "accepted":
			rep.Imported = append(rep.Imported, rc.ServerID+"@"+rc.Revision)
		}
	}
	var gone []string
	gone = append(gone, l.applyRevocations(actor, &rep)...)
	gone = append(gone, l.applyExpiry(actor, &rep)...)
	return rep, gone
}

// rejectedBefore reports whether the package directory's current index
// was already rejected, so a periodic scan writes one receipt per attempt
// rather than one per interval. It lives in memory: a restart retries once.
func (l *Library) rejectedBefore(dir, sha string) bool {
	return l.rejected != nil && l.rejected[dir] == sha
}

func (l *Library) markRejected(dir, sha string) {
	if l.rejected == nil {
		l.rejected = map[string]string{}
	}
	l.rejected[dir] = sha
}

func (l *Library) applyRevocations(actor string, rep *ScanReport) []string {
	entries, anchors, err := l.readFeed()
	if err != nil {
		rep.Errors = append(rep.Errors, err.Error())
		return nil
	}
	var gone []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		rv, err := packaging.VerifyRevocation(filepath.Join(l.dir, packaging.RevocationsDir, e.Name()), anchors.Resolver())
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("revocation %s: %v", e.Name(), err))
			continue
		}
		key := rv.ServerID + "@" + rv.Revision
		if _, done := l.doc.Revocations[key]; done {
			continue
		}
		if l.doc.Revocations == nil {
			l.doc.Revocations = map[string]string{}
		}
		l.doc.Revocations[key] = rv.RevokedAt
		if r := l.find(rv.ServerID, rv.Revision); r != nil && r.State != StateRevoked && r.State != StateRetired {
			if r.State == StateEnabled {
				gone = append(gone, r.Alias)
			}
			l.setState(r, StateRevoked, "revocation entry: "+rv.Reason, actor)
			_ = l.evidence(audit.Event{Origin: "E-13", Outcome: "revoked", ReasonCode: ReasonRevoked, ServerRevision: key,
				Detail: map[string]any{"reason": rv.Reason, "signer_key_id": rv.SignerKeyID, "revoked_at": rv.RevokedAt}})
		}
		rep.Revoked = append(rep.Revoked, key)
	}
	if err := l.save(); err != nil {
		rep.Errors = append(rep.Errors, err.Error())
	}
	return gone
}

// expired reports whether a revision's manifest expiry or re-curation date
// has passed (FR-5.8). Dates are whole days in UTC; a revision expires at
// the end of the named day.
func (l *Library) expired(r *Revision) (bool, string) {
	for _, d := range []struct{ v, what string }{{r.Expires, "manifest expiry"}, {r.RecurationDue, "re-curation date"}} {
		if d.v == "" {
			continue
		}
		t, err := time.Parse("2006-01-02", d.v)
		if err != nil {
			return true, d.what + " is unreadable"
		}
		if !l.now().UTC().Before(t.Add(24 * time.Hour)) {
			return true, d.what + " " + d.v + " has passed"
		}
	}
	return false, ""
}

func (l *Library) applyExpiry(actor string, rep *ScanReport) []string {
	var gone []string
	changed := false
	for _, r := range l.doc.Revisions {
		if r.State != StateEnabled && r.State != StateVerifiedDisabled {
			continue
		}
		if exp, why := l.expired(r); exp {
			if r.State == StateEnabled {
				gone = append(gone, r.Alias)
			}
			l.setState(r, StateSuspended, why, actor)
			changed = true
			_ = l.evidence(audit.Event{Outcome: "suspended", ReasonCode: ReasonExpired, ServerRevision: r.Key(), Detail: map[string]any{"reason": why}})
			rep.Suspended = append(rep.Suspended, r.Key())
		}
	}
	if changed {
		if err := l.save(); err != nil {
			rep.Errors = append(rep.Errors, err.Error())
		}
	}
	return gone
}

// EnableOptions configure Enable.
type EnableOptions struct {
	Actor string
	Alias string // default the manifest alias
	// Standalone is true when instances run unconfined; high-risk
	// revisions are then refused (SR-4-1).
	Standalone bool
}

// Enable changes a revision to enabled (SR-3.9-1). The caller has
// authenticated the actor as an Administrator: the control API, or the
// operator's offline smcpctl under the state directory's permissions. Any
// other enabled revision of the same server returns to verified-disabled.
func (l *Library) Enable(id, rev string, o EnableOptions) (Revision, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.find(id, rev)
	if r == nil {
		return Revision{}, errf(ReasonUnknown, "no revision %s@%s", id, rev)
	}
	err := l.checkEnable(r, o)
	if err != nil {
		_ = l.evidence(audit.Event{Outcome: "enable_refused", ReasonCode: packaging.ReasonOf(err), ServerRevision: r.Key(), Detail: map[string]any{"actor": o.Actor, "error": err.Error()}})
		return *r, err
	}
	m, _, err := l.Manifest(id, rev)
	if err != nil {
		return *r, err
	}
	bind, err := EnablementDigest(m)
	if err != nil {
		return *r, err
	}
	for _, x := range l.doc.Revisions {
		if x != r && x.ServerID == id && x.State == StateEnabled {
			l.setState(x, StateVerifiedDisabled, "superseded by "+rev, o.Actor)
		}
	}
	if o.Alias != "" {
		r.Alias = o.Alias
	}
	r.EnablementSHA256 = bind
	l.setState(r, StateEnabled, "enabled", o.Actor)
	if err := l.save(); err != nil {
		return *r, err
	}
	if err := l.evidence(audit.Event{Outcome: "enabled", ServerRevision: r.Key(), Detail: map[string]any{"actor": o.Actor, "alias": r.Alias, "enablement_sha256": bind}}); err != nil {
		return *r, err
	}
	return *r, nil
}

func (l *Library) checkEnable(r *Revision, o EnableOptions) error {
	if r.State == StateEnabled {
		return nil
	}
	if !allowed(r.State, StateEnabled) {
		return errf(ReasonState, "%s is %s and cannot be enabled", r.Key(), r.State)
	}
	if exp, why := l.expired(r); exp {
		return errf(ReasonExpired, "%s: %s", r.Key(), why)
	}
	m, _, err := l.Manifest(r.ServerID, r.Revision)
	if err != nil {
		return err
	}
	if o.Standalone && m.HighestRisk() == "high" {
		return errf(ReasonProfile, "%s has risk class high; the Standalone profile cannot confine it (SR-4-1)", r.Key())
	}
	if m.Stateful {
		// The manifest schema has no handle contract yet (SR-3.14-1).
		return errf(ReasonStateful, "%s declares stateful tools without a handle contract", r.Key())
	}
	alias := r.Alias
	if o.Alias != "" {
		alias = o.Alias
	}
	if !aliasRE.MatchString(alias) {
		return errf(ReasonAliasConflict, "alias %q must be 1 to 16 characters of a-z 0-9", alias)
	}
	for _, x := range l.doc.Revisions {
		if x.ServerID != r.ServerID && x.State == StateEnabled && x.Alias == alias {
			return errf(ReasonAliasConflict, "alias %q is used by the enabled server %s; choose another alias", alias, x.Key())
		}
	}
	seen := map[string]string{}
	for _, t := range m.Tools {
		pub := backend.PublicName(alias, t.Name)
		if prev, dup := seen[pub]; dup {
			return errf(ReasonNameCollision, "tools %q and %q both map to public name %q (FR-1.49)", prev, t.Name, pub)
		}
		if len(pub) > 64 {
			return errf(ReasonNameCollision, "tool %q: public name %q exceeds 64 characters", t.Name, pub)
		}
		seen[pub] = t.Name
	}
	return nil
}

// SetState applies an administrator state change: verified-disabled
// (disable), retired or suspended. It returns the alias when an enabled
// revision left the enabled state.
func (l *Library) SetState(id, rev, state, reason, actor string) (Revision, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.find(id, rev)
	if r == nil {
		return Revision{}, "", errf(ReasonUnknown, "no revision %s@%s", id, rev)
	}
	if state == StateEnabled || state == StateRevoked {
		return *r, "", errf(ReasonState, "use enable or a signed revocation entry for %s", state)
	}
	if r.State == state {
		return *r, "", nil
	}
	if !allowed(r.State, state) {
		return *r, "", errf(ReasonState, "%s is %s and cannot become %s", r.Key(), r.State, state)
	}
	gone := ""
	if r.State == StateEnabled {
		gone = r.Alias
	}
	l.setState(r, state, reason, actor)
	if err := l.save(); err != nil {
		return *r, gone, err
	}
	if state == StateRetired {
		l.collect()
	}
	return *r, gone, l.evidence(audit.Event{Outcome: state, ServerRevision: r.Key(), Detail: map[string]any{"actor": actor, "reason": reason}})
}

// collect removes cached artifacts no non-retired revision references
// (FR-5.39); the caller holds mu.
func (l *Library) collect() {
	keep := map[string]bool{}
	for _, r := range l.doc.Revisions {
		if r.State != StateRetired {
			keep[r.ArtifactSHA256] = true
		}
	}
	for _, r := range l.doc.Revisions {
		if r.State == StateRetired && !keep[r.ArtifactSHA256] {
			os.Remove(l.ArtifactPath(r.ArtifactSHA256))
			packaging.MakeWritable(l.TreePath(r.ArtifactSHA256))
			os.RemoveAll(l.TreePath(r.ArtifactSHA256))
		}
	}
}

// EnablementDigest is the SHA-256 of the manifest's canonical tool
// definitions and declared capabilities (SR-3.7-1).
func EnablementDigest(m *packaging.Manifest) (string, error) {
	raw, err := json.Marshal(map[string]any{"tools": m.CanonicalTools(), "capabilities": m.Capabilities, "secrets": m.Secrets, "launch": m.Launch})
	if err != nil {
		return "", err
	}
	return packaging.SHA256Hex(raw), nil
}
