package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Secret Use Policy authoring for the G-02 structured editor (FR-8.4):
//
//	GET  /api/v1/secret-use-policy           the active document, its file and the published revisions
//	POST /api/v1/secret-use-policy/validate  {document} -> {revision, digest, bindings} or 422
//	POST /api/v1/secret-use-policy           {document, reason} -> publish to use_policy_file and activate
//	POST /api/v1/secret-use-policy/rollback  {revision, reason} -> publish an archived revision again
//
// A published document is validated like a reloaded file (CompileUsePolicy),
// recorded in the journal before it takes effect, written atomically to the
// configured use_policy_file (so it survives a restart) and archived under
// <state>/secrets/use-policy/<revision>.json for rollback. The routes are
// Administrator-only: secret operations belong to the Administrator alone
// (Appendix C).

// usePolicyRevision is the archive file name rule: the schema's revision
// pattern.
var usePolicyRevision = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var publishMu sync.Mutex

func (s *Service) registerUsePolicy(h Handler) {
	h.Handle("GET /api/v1/secret-use-policy", s.usePolicyGet)
	h.Handle("POST /api/v1/secret-use-policy/validate", s.usePolicyValidate)
	h.Handle("POST /api/v1/secret-use-policy", s.usePolicyPublish)
	h.Handle("POST /api/v1/secret-use-policy/rollback", s.usePolicyRollback)
}

func (s *Service) usePolicyArchive() string {
	return filepath.Join(s.cfg.State.Dir, "secrets", "use-policy")
}

// UsePolicyRevision is one archived (published) Secret Use Policy.
type UsePolicyRevision struct {
	Revision    string    `json:"revision"`
	Digest      string    `json:"digest"`
	PublishedAt time.Time `json:"published_at"`
}

func (s *Service) usePolicyRevisions() []UsePolicyRevision {
	ents, _ := os.ReadDir(s.usePolicyArchive())
	out := []UsePolicyRevision{}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.usePolicyArchive(), name))
		if err != nil {
			continue
		}
		u, err := CompileUsePolicy(raw, s.cfg.Servers)
		if err != nil {
			continue
		}
		info, _ := e.Info()
		r := UsePolicyRevision{Revision: u.Revision, Digest: u.Digest}
		if info != nil {
			r.PublishedAt = info.ModTime().UTC()
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublishedAt.After(out[j].PublishedAt) })
	return out
}

func (s *Service) usePolicyGet(w http.ResponseWriter, r *http.Request) {
	use := s.Broker.UsePolicy()
	out := map[string]any{"file": s.Settings.UsePolicyFile, "revisions": s.usePolicyRevisions()}
	if use != nil {
		out["active"] = map[string]any{"revision": use.Revision, "digest": use.Digest, "bindings": len(use.bindings)}
	}
	if s.Settings.UsePolicyFile != "" {
		if raw, err := os.ReadFile(s.Settings.UsePolicyFile); err == nil && json.Valid(raw) {
			out["document"] = json.RawMessage(raw)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) usePolicyValidate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Document json.RawMessage `json:"document"`
	}
	if err := decode(r, &body); err != nil || len(body.Document) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {\"document\": {...}}")
		return
	}
	u, err := CompileUsePolicy(body.Document, s.cfg.Servers)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "use_policy_invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": u.Revision, "digest": u.Digest, "bindings": len(u.bindings)})
}

func (s *Service) usePolicyPublish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Document json.RawMessage `json:"document"`
		Reason   string          `json:"reason"`
	}
	if err := decode(r, &body); err != nil || len(body.Document) == 0 || len(body.Reason) > 1000 {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {\"document\": {...}, \"reason\": \"...\"} with a reason of at most 1000 characters")
		return
	}
	s.publishUsePolicy(w, r, body.Document, body.Reason, "published", true)
}

func (s *Service) usePolicyRollback(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Revision string `json:"revision"`
		Reason   string `json:"reason"`
	}
	if err := decode(r, &body); err != nil || !usePolicyRevision.MatchString(body.Revision) || len(body.Reason) > 1000 {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {\"revision\": \"...\", \"reason\": \"...\"}")
		return
	}
	raw, err := os.ReadFile(filepath.Join(s.usePolicyArchive(), body.Revision+".json"))
	if err != nil {
		writeError(w, http.StatusNotFound, "revision_not_found", "no published Secret Use Policy revision "+body.Revision)
		return
	}
	s.publishUsePolicy(w, r, raw, body.Reason, "rolled_back", false)
}

// publishUsePolicy validates doc, records the activation, writes the file
// and the archive copy and activates the policy. A new publication must
// carry a revision ID that differs from the active one and from any
// archived revision with other content; a rollback republishes an archived
// document as it is.
func (s *Service) publishUsePolicy(w http.ResponseWriter, r *http.Request, doc []byte, reason, action string, fresh bool) {
	if s.Settings.UsePolicyFile == "" {
		writeError(w, http.StatusConflict, "use_policy_file_unset", "set [secrets] use_policy_file in smcp.toml to publish a Secret Use Policy from the console")
		return
	}
	u, err := CompileUsePolicy(doc, s.cfg.Servers)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "use_policy_invalid", err.Error())
		return
	}
	publishMu.Lock()
	defer publishMu.Unlock()
	archived := filepath.Join(s.usePolicyArchive(), u.Revision+".json")
	if fresh {
		if cur := s.Broker.UsePolicy(); cur != nil && cur.Revision == u.Revision {
			writeError(w, http.StatusConflict, "revision_exists", "revision "+u.Revision+" is active; give the draft a new revision ID")
			return
		}
		if prev, err := os.ReadFile(archived); err == nil {
			if pu, err := CompileUsePolicy(prev, s.cfg.Servers); err == nil && pu.Digest != u.Digest {
				writeError(w, http.StatusConflict, "revision_exists", "revision "+u.Revision+" was published with other content; give the draft a new revision ID")
				return
			}
		}
	}
	b := s.Broker
	b.mu.Lock()
	rec := b.rec
	b.mu.Unlock()
	if rec == nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", ErrNoEvidence.Error())
		return
	}
	detail := map[string]any{"actor": adminapi.Actor(r), "digest": u.Digest, "bindings": len(u.bindings), "action": action, "file": s.Settings.UsePolicyFile}
	if reason != "" {
		detail["reason"] = reason
	}
	if err := rec.Commit(audit.Event{Class: "admin", Origin: "E-05", Outcome: "activated", ReasonCode: "SECRET_USE_POLICY_ACTIVATED", PolicyRevision: u.Revision,
		PolicyStatus: "not_evaluated", Detail: detail}); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
		return
	}
	if err := writeFileAtomic(s.Settings.UsePolicyFile, doc); err != nil {
		writeError(w, http.StatusInternalServerError, "write_failed", fmt.Sprintf("writing %s: %v", s.Settings.UsePolicyFile, err))
		return
	}
	if err := os.MkdirAll(s.usePolicyArchive(), 0o700); err == nil {
		if _, err := os.Stat(archived); errors.Is(err, os.ErrNotExist) {
			_ = writeFileAtomic(archived, doc)
		}
	}
	b.SetUsePolicy(u)
	writeJSON(w, http.StatusOK, map[string]any{"revision": u.Revision, "digest": u.Digest, "bindings": len(u.bindings), "action": action})
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory (mode 0600) and a rename.
func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".use-policy-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
