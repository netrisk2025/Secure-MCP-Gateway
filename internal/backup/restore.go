package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policystore"
	"github.com/ethan03805/secure-mcp-gateway/internal/remote"
)

// RestoreOptions configure Restore. The Gateway must not be running.
type RestoreOptions struct {
	Archive    string
	Decryption Decryption
	// Target paths: the state directory, configuration file and policy
	// file of the installation being restored.
	StateDir   string
	ConfigPath string
	PolicyPath string
	// VerifyOnly decrypts and verifies into the isolated directory and
	// removes it without changing the installation.
	VerifyOnly bool
	Now        func() time.Time
	// GraphBackend replaces the Neo4j connection of the restored
	// configuration's [graph] table for the mirror rebuild (tests).
	GraphBackend graph.Backend
	// GraphTimeout bounds the wait for the graph database and the rebuild
	// (default 5 minutes).
	GraphTimeout time.Duration
	// GraphBestEffort reports a failed mirror rebuild in the report
	// instead of refusing the restore (the rollback of a failed upgrade,
	// which must not depend on the graph database).
	GraphBestEffort bool
}

// Revocation is one revocation found in a journal. Restore re-applies
// every one found in the restored and the current journal by writing them
// to state/revocations.json, which the elements that issue credentials
// read at startup.
type Revocation struct {
	EventID    string `json:"event_id"`
	Time       string `json:"time"`
	Class      string `json:"class"`
	ReasonCode string `json:"reason_code"`
	SessionID  string `json:"session_id,omitempty"`
	Principal  string `json:"principal_id,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	// ServerRevision is the package revision of a package revocation.
	ServerRevision string `json:"server_revision,omitempty"`
	Detail         any    `json:"detail,omitempty"`
}

// RevocationsFile holds the re-applied revocations under the state
// directory.
const RevocationsFile = "revocations.json"

// RestoreReport describes a restore.
type RestoreReport struct {
	Archive          string       `json:"archive"`
	ChecksumVerified bool         `json:"checksum_verified"`
	Manifest         Manifest     `json:"manifest"`
	JournalSegments  int          `json:"journal_segments"`
	JournalEvents    int          `json:"journal_events"`
	JournalKeys      int          `json:"journal_keys"`
	PolicyRevision   string       `json:"policy_revision"`
	Revocations      []Revocation `json:"revocations"`
	// DirectoryChanges counts the principal suspensions and credential
	// revocations re-applied to the restored principal directory.
	DirectoryChanges int `json:"directory_changes"`
	// PackageRevocations and ClientRevocations count the package revisions
	// and dynamic client registrations whose revocation was re-applied to
	// the restored registries.
	PackageRevocations int `json:"package_revocations"`
	ClientRevocations  int `json:"client_revocations"`
	// PolicyStoreRevision is the active revision of the restored Policy
	// Store and PolicyRevisionsVerified the number of signed revisions
	// verified; both are empty when the archive holds no Policy Store.
	PolicyStoreRevision     string `json:"policy_store_revision,omitempty"`
	PolicyRevisionsVerified int    `json:"policy_revisions_verified"`
	GraphMirror             string `json:"graph_mirror"`
	Isolated                string `json:"isolated_dir"`
	PreviousState           string `json:"previous_state,omitempty"`
	Applied                 bool   `json:"applied"`
}

// Restore decrypts the archive into an isolated directory next to the
// state directory, verifies the archive checksum (when the .sha256 file is
// present), every entry against the manifest, the journal chain,
// signatures and anchor, the policy file and the configuration, collects
// the revocations recorded in the restored and the current journal, and
// only then swaps the restored state, configuration and policy into place
// (SR-7.8-1). The previous state directory is kept as
// <state>.pre-restore-<time>, so evidence written after the backup is not
// lost.
func Restore(o RestoreOptions) (RestoreReport, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	rep := RestoreReport{Archive: o.Archive, GraphMirror: "not configured; nothing to rebuild"}
	ok, err := VerifyChecksum(o.Archive)
	if err != nil {
		return rep, err
	}
	rep.ChecksumVerified = ok
	stamp := o.Now().UTC().Format("20060102T150405Z")
	parent := filepath.Dir(filepath.Clean(o.StateDir))
	iso, err := os.MkdirTemp(parent, ".smcp-restore-"+stamp+"-")
	if err != nil {
		return rep, err
	}
	rep.Isolated = iso
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(iso)
		}
	}()
	if rep.Manifest, err = Extract(o.Archive, iso, o.Decryption); err != nil {
		return rep, err
	}
	rstate := filepath.Join(iso, "state")
	root, err := keys.LoadEvidenceTrustRoot(rstate)
	if err != nil {
		return rep, fmt.Errorf("restored evidence key: %w", err)
	}
	jr, err := audit.Verify(filepath.Join(rstate, "journal"), root)
	if err != nil {
		return rep, fmt.Errorf("restored journal does not verify: %w", err)
	}
	rep.JournalSegments, rep.JournalEvents, rep.JournalKeys = jr.Segments, jr.Events, len(jr.Keys)
	cfgFile, polFile := single(iso, "config"), single(iso, "policy")
	if cfgFile == "" || polFile == "" {
		return rep, errors.New("archive lacks the configuration or the policy file")
	}
	raw, err := os.ReadFile(cfgFile)
	if err != nil {
		return rep, err
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return rep, fmt.Errorf("restored configuration: %w", err)
	}
	snap, err := policy.Load(polFile)
	if err != nil {
		return rep, fmt.Errorf("restored policy: %w", err)
	}
	rep.PolicyRevision = snap.Revision
	if exists(filepath.Join(rstate, filepath.Dir(policystore.ControlFile))) {
		// The signed Policy Store: every revision file and the control
		// record must verify under the restored policy-signing key.
		st, err := policystore.Open(rstate)
		if err != nil {
			return rep, fmt.Errorf("restored Policy Store: %w", err)
		}
		active, _, err := st.Active()
		if err != nil {
			return rep, fmt.Errorf("restored Policy Store: %w", err)
		}
		rep.PolicyStoreRevision, rep.PolicyRevisionsVerified = active.Record.Revision, len(st.List())
	}
	revs, err := revocations(filepath.Join(rstate, "journal"))
	if err != nil {
		return rep, err
	}
	if cur := filepath.Join(o.StateDir, "journal"); exists(cur) {
		more, err := revocations(cur)
		if err != nil {
			return rep, fmt.Errorf("current journal: %w", err)
		}
		revs = mergeRevocations(revs, more)
	}
	rep.Revocations = revs
	if err := writeRevocations(rstate, revs); err != nil {
		return rep, err
	}
	enabled := map[string]string{}
	for _, jd := range []string{filepath.Join(rstate, "journal"), filepath.Join(o.StateDir, "journal")} {
		if exists(jd) {
			if err := enablements(jd, enabled); err != nil {
				return rep, err
			}
		}
	}
	if rep.DirectoryChanges, err = applyDirectoryRevocations(rstate, revs, enabled); err != nil {
		return rep, err
	}
	pkgs, clients := map[string]string{}, map[string]time.Time{}
	for _, r := range revs {
		switch {
		case r.Class == "package" && r.ServerRevision != "":
			pkgs[r.ServerRevision] = r.Time
		case r.ReasonCode == "DCR_REVOKED" && r.ClientID != "":
			at, _ := time.Parse(time.RFC3339Nano, r.Time)
			clients[r.ClientID] = at
		}
	}
	if rep.PackageRevocations, err = library.ReapplyRevocations(rstate, pkgs, o.Now()); err != nil {
		return rep, fmt.Errorf("package registry: %w", err)
	}
	if rep.ClientRevocations, err = remote.ReapplyRevocations(rstate, clients); err != nil {
		return rep, fmt.Errorf("remote client registry: %w", err)
	}
	if o.VerifyOnly {
		if graphEnabled(cfg, o.GraphBackend) {
			rep.GraphMirror = "configured; not rebuilt (verify only)"
		}
		return rep, nil
	}
	if graphEnabled(cfg, o.GraphBackend) {
		switch err := rebuildGraph(cfg, rstate, o); {
		case err == nil:
			rep.GraphMirror = "rebuilt from the restored journal"
		case o.GraphBestEffort:
			rep.GraphMirror = "not rebuilt: " + err.Error() + "; rebuild it with smcpctl graph rebuild --yes"
		default:
			return rep, fmt.Errorf("graph mirror rebuild from the restored journal: %w (start the graph database, or set [graph] enabled = false, and restore again)", err)
		}
	}

	// Swap. The previous state stays next to the restored one.
	if exists(o.StateDir) {
		rep.PreviousState = o.StateDir + ".pre-restore-" + stamp
		if err := os.Rename(o.StateDir, rep.PreviousState); err != nil {
			return rep, err
		}
	}
	if err := os.Rename(rstate, o.StateDir); err != nil {
		if rep.PreviousState != "" {
			_ = os.Rename(rep.PreviousState, o.StateDir)
		}
		return rep, err
	}
	for _, f := range []struct{ src, dst string }{{cfgFile, o.ConfigPath}, {polFile, o.PolicyPath}} {
		if f.dst == "" {
			continue
		}
		if exists(f.dst) {
			if err := copyFile(f.dst, f.dst+".pre-restore-"+stamp, 0o600); err != nil {
				return rep, err
			}
		}
		if err := copyFile(f.src, f.dst, 0o600); err != nil {
			return rep, err
		}
	}
	rep.Applied = true
	return rep, nil
}

// single returns the one file in iso/<dir>, or "".
func single(iso, dir string) string {
	es, err := os.ReadDir(filepath.Join(iso, dir))
	if err != nil || len(es) != 1 || es[0].IsDir() {
		return ""
	}
	return filepath.Join(iso, dir, es[0].Name())
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return keys.WriteFileAtomic(dst, b, mode)
}

// isRevocation reports whether an event revokes a credential, a session,
// a principal or a server. Elements record revocations with a reason code
// ending in _REVOKED or with class "revocation"; a principal suspension
// (PRINCIPAL_SUSPENDED) revokes the principal (SR-2.4-1).
func isRevocation(ev audit.Event) bool {
	return ev.Class == "revocation" || strings.HasSuffix(ev.ReasonCode, "_REVOKED") || ev.Outcome == "revoked" || ev.ReasonCode == reasonPrincipalSuspended
}

// Reason codes of the principal directory (internal/principals).
const (
	reasonPrincipalSuspended = "PRINCIPAL_SUSPENDED"
	reasonPrincipalEnabled   = "PRINCIPAL_ENABLED"
	reasonCredentialRevoked  = "CREDENTIAL_REVOKED"
	principalsFile           = "principals.json" // principals.File
)

// enablements returns, per principal, the time of the latest
// PRINCIPAL_ENABLED event in the journal.
func enablements(journalDir string, into map[string]string) error {
	evs, err := audit.ReadEvents(journalDir)
	if err != nil {
		return err
	}
	for _, ev := range evs {
		if ev.ReasonCode == reasonPrincipalEnabled && ev.PrincipalID != "" && after(ev.Time, into[ev.PrincipalID]) {
			into[ev.PrincipalID] = ev.Time
		}
	}
	return nil
}

// applyDirectoryRevocations re-applies principal suspensions and
// credential revocations to the restored principal directory
// (state/principals.json) before service starts (SR-7.8-1): a backup taken
// before a revocation must not bring the revoked principal or credential
// back. A suspension is skipped when the principal was enabled again
// later. The file is edited as JSON so that fields this package does not
// know are kept. It returns the number of changes made.
func applyDirectoryRevocations(rstate string, revs []Revocation, enabled map[string]string) (int, error) {
	path := filepath.Join(rstate, principalsFile)
	st := map[string]any{}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		st["version"] = 1
	case err != nil:
		return 0, err
	default:
		if err := json.Unmarshal(raw, &st); err != nil {
			return 0, fmt.Errorf("restored %s: %w", principalsFile, err)
		}
	}
	suspended, _ := st["suspended"].(map[string]any)
	if suspended == nil {
		suspended = map[string]any{}
	}
	creds, _ := st["credentials"].([]any)
	changed := 0
	for _, r := range revs {
		switch r.ReasonCode {
		case reasonPrincipalSuspended:
			if r.Principal == "" || after(enabled[r.Principal], r.Time) {
				continue
			}
			if _, ok := suspended[r.Principal]; !ok {
				reason, _ := detailString(r.Detail, "reason")
				suspended[r.Principal] = map[string]any{"by": "restore", "at": r.Time, "reason": "re-applied from journal event " + r.EventID + ": " + reason}
				changed++
			}
		case reasonCredentialRevoked:
			id, _ := detailString(r.Detail, "client_id")
			for _, c := range creds {
				m, _ := c.(map[string]any)
				if m != nil && m["client_id"] == id && m["revoked_at"] == nil {
					m["revoked_at"], m["revoked_by"] = r.Time, "restore"
					changed++
				}
			}
		}
	}
	if changed == 0 {
		return 0, nil
	}
	st["suspended"] = suspended
	if creds != nil {
		st["credentials"] = creds
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return 0, err
	}
	return changed, keys.WriteFileAtomic(path, append(b, '\n'), 0o600)
}

// after reports whether event time a is later than b. Journal times are
// RFC 3339 with variable fractional digits, so they are compared as times;
// an empty or unparsable time is the earliest.
func after(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339Nano, a)
	if errA != nil {
		return false
	}
	tb, errB := time.Parse(time.RFC3339Nano, b)
	return errB != nil || ta.After(tb)
}

func detailString(d any, k string) (string, bool) {
	m, ok := d.(map[string]any)
	if !ok {
		return "", false
	}
	s, ok := m[k].(string)
	return s, ok
}

func revocations(journalDir string) ([]Revocation, error) {
	evs, err := audit.ReadEvents(journalDir)
	if err != nil {
		return nil, err
	}
	var out []Revocation
	for _, ev := range evs {
		if isRevocation(ev) {
			out = append(out, Revocation{EventID: ev.EventID, Time: ev.Time, Class: ev.Class, ReasonCode: ev.ReasonCode, SessionID: ev.SessionID, Principal: ev.PrincipalID,
				ClientID: ev.ClientID, ServerRevision: ev.ServerRevision, Detail: ev.Detail})
		}
	}
	return out, nil
}

func mergeRevocations(a, b []Revocation) []Revocation {
	seen := map[string]bool{}
	var out []Revocation
	for _, r := range append(a, b...) {
		if !seen[r.EventID] {
			seen[r.EventID] = true
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, k int) bool { return after(out[k].Time, out[i].Time) })
	return out
}

func writeRevocations(stateDir string, revs []Revocation) error {
	if revs == nil {
		revs = []Revocation{}
	}
	b, err := jsonIndent(revs)
	if err != nil {
		return err
	}
	return keys.WriteFileAtomic(filepath.Join(stateDir, RevocationsFile), b, 0o600)
}

// graphEnabled reports whether the restored configuration mirrors the
// journal into a graph database.
func graphEnabled(cfg *config.Config, b graph.Backend) bool {
	return b != nil || cfg.Graph.Enabled
}

// rebuildGraph wipes the graph mirror and rebuilds it from the restored
// journal, before the restored state is swapped in and service starts
// (SR-7.8-1). The graph database settings, password file included, are
// read from the restored configuration and state.
func rebuildGraph(cfg *config.Config, rstate string, o RestoreOptions) error {
	gcfg := *cfg
	gcfg.State.Dir = rstate
	m, err := graph.New(graph.Options{Config: &gcfg, Backend: o.GraphBackend, JournalDir: filepath.Join(rstate, "journal"), Log: diag.Discard(), Now: o.Now})
	if err != nil {
		return err
	}
	timeout := o.GraphTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	m.Start(ctx, nil)
	defer m.Close()
	for {
		if _, err := m.DAS(); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			st := m.Status(context.Background(), false)
			return fmt.Errorf("graph database not ready (%s: %s)", st.State, st.Error)
		case <-time.After(50 * time.Millisecond):
		}
	}
	return m.Rebuild(ctx)
}
