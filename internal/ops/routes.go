package ops

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/backup"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

func (r *Runtime) routes() {
	h := r.app.Admin.Handle
	h("GET /api/v1/health/status", r.handleStatus)
	h("POST /api/v1/health/ack", r.handleAck)
	h("GET /api/v1/keys", r.handleKeys)
	h("POST /api/v1/keys/rotate", r.handleRotate)
	h("GET /api/v1/backup", r.handleBackups)
	h("POST /api/v1/backup", r.handleBackup)
	h("POST /api/v1/config/reload", r.handleReload)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (r *Runtime) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, r.Status())
}

func (r *Runtime) handleAck(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Cause string `json:"cause"`
	}
	if err := decode(req, &body); err != nil || body.Cause == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {cause}")
		return
	}
	if err := r.mon.Ack(body.Cause, adminapi.Actor(req)); err != nil {
		if errors.Is(err, health.ErrNotLatched) {
			writeError(w, http.StatusConflict, "not_latched", err.Error())
			return
		}
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, r.Status())
}

func (r *Runtime) handleKeys(w http.ResponseWriter, _ *http.Request) {
	st, err := keys.ReadStatus(r.app.Config.State.Dir, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keys_unreadable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// RotateRequest is the body of POST /api/v1/keys/rotate.
type RotateRequest struct {
	Kind    string `json:"kind"`              // tls, ca, evidence
	Overlap string `json:"overlap,omitempty"` // ca: Go duration, default 168h
	Finish  bool   `json:"finish,omitempty"`  // ca: end the overlap now
}

func (r *Runtime) handleRotate(w http.ResponseWriter, req *http.Request) {
	var body RotateRequest
	if err := decode(req, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {kind: tls|ca|evidence, overlap, finish}")
		return
	}
	res, err := r.Rotate(body, adminapi.Actor(req))
	switch {
	case errors.Is(err, errBadRotate):
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, keys.ErrRotationInProgress):
		writeError(w, http.StatusConflict, "rotation_in_progress", err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, "rotation_failed", err.Error())
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

var errBadRotate = errors.New("kind must be tls, ca or evidence")

// Rotate performs one rotation (FR-17.7) and records it.
func (r *Runtime) Rotate(req RotateRequest, actor string) (map[string]any, error) {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	cfg := r.app.Config
	names := ListenerNames(cfg)
	now := time.Now()
	switch req.Kind {
	case "tls":
		st, err := keys.RotateLeaf(cfg.State.Dir, names...)
		if err != nil {
			return nil, err
		}
		r.commit("key_rotated", "LISTENER_CERT_ROTATED", actor, map[string]any{"kind": "tls", "not_after": st.LeafNotAfter})
		return map[string]any{"kind": "tls", "listener_not_after": st.LeafNotAfter, "uncovered_names": st.Uncovered}, nil
	case "ca":
		if req.Finish {
			st, err := keys.FinishCARotation(cfg.State.Dir, now, names...)
			if err != nil {
				return nil, err
			}
			r.commit("key_rotated", "SERVER_CA_ACTIVATED", actor, map[string]any{"kind": "ca", "stage": "finished"})
			return map[string]any{"kind": "ca", "stage": "finished", "ca_not_after": st.CANotAfter, "listener_not_after": st.LeafNotAfter}, nil
		}
		overlap := keys.DefaultCAOverlap
		if req.Overlap != "" {
			d, err := time.ParseDuration(req.Overlap)
			if err != nil || d < 0 {
				return nil, fmt.Errorf("%w: overlap must be a non-negative duration", errBadRotate)
			}
			overlap = d
		}
		rot, st, err := keys.BeginCARotation(cfg.State.Dir, now, overlap, names...)
		if err != nil {
			return nil, err
		}
		stage := "overlap"
		if overlap == 0 {
			stage = "finished"
		}
		r.commit("key_rotated", "SERVER_CA_ROTATION_STARTED", actor, map[string]any{"kind": "ca", "stage": stage, "switch_at": rot.SwitchAt, "next_ca_sha256": rot.NextCA.SHA256})
		return map[string]any{"kind": "ca", "stage": stage, "switch_at": rot.SwitchAt, "next_ca": rot.NextCA, "listener_not_after": st.LeafNotAfter,
			"trust_bundle": filepath.Join(cfg.State.Dir, keys.CACertFile)}, nil
	case "evidence":
		next, err := keys.NewEvidenceKey()
		if err != nil {
			return nil, err
		}
		if err := keys.StagePendingEvidenceKey(cfg.State.Dir, next); err != nil {
			return nil, err
		}
		if err := r.app.Journal.RotateKey(next); err != nil {
			_ = os.Remove(filepath.Join(cfg.State.Dir, keys.EvidencePendingKeyFile))
			return nil, err
		}
		if err := keys.CommitPendingEvidenceKey(cfg.State.Dir); err != nil {
			// The journal already uses the new key; the next start finishes
			// the commit from the pending file (keys.ResolvePendingEvidenceKey).
			return nil, fmt.Errorf("journal switched keys but the new key was not committed; restart to finish: %w", err)
		}
		pub, err := keys.LoadEvidencePublicKey(cfg.State.Dir)
		if err != nil {
			return nil, err
		}
		r.commit("key_rotated", "EVIDENCE_KEY_ROTATED", actor, map[string]any{"kind": "evidence", "public_key": fmt.Sprintf("%x", []byte(pub))})
		return map[string]any{"kind": "evidence", "public_key": fmt.Sprintf("%x", []byte(pub))}, nil
	}
	return nil, errBadRotate
}

func (r *Runtime) handleBackups(w http.ResponseWriter, _ *http.Request) {
	list, err := backup.ReadIndex(r.app.Config.Backup.Dir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "index_unreadable", err.Error())
		return
	}
	if list == nil {
		list = []backup.IndexEntry{}
	}
	// configured is what the G-01 first-run checklist shows (FR-8.31): a
	// backup schedule is set or a backup has been taken.
	scheduled := r.app.Config.Backup.Interval.Duration > 0
	writeJSON(w, http.StatusOK, map[string]any{"dir": r.app.Config.Backup.Dir, "backups": list, "scheduled": scheduled, "configured": scheduled || len(list) > 0})
}

// BackupRequest is the body of POST /api/v1/backup.
type BackupRequest struct {
	Passphrase string            `json:"passphrase,omitempty"`
	Recipients []string          `json:"recipients,omitempty"`
	Optional   map[string]string `json:"optional,omitempty"` // name -> path (Observation Store copy, graph dump)
}

func (r *Runtime) handleBackup(w http.ResponseWriter, req *http.Request) {
	var body BackupRequest
	if err := decode(req, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {passphrase} or {recipients}")
		return
	}
	res, err := r.Backup(body, adminapi.Actor(req))
	switch {
	case errors.Is(err, backup.ErrUnencrypted):
		writeError(w, http.StatusBadRequest, "BACKUP_UNENCRYPTED_REFUSED", err.Error())
	case errors.Is(err, errDrain):
		writeError(w, http.StatusServiceUnavailable, "BACKUP_DRAIN_TIMEOUT", err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, "BACKUP_FAILED", err.Error())
	default:
		writeJSON(w, http.StatusOK, res)
	}
}

var errDrain = errors.New("in-flight calls did not finish within the drain timeout; the backup was not taken")

// Backup runs the SR-7.7-1 procedure: stop dispatch, drain in-flight
// calls, seal the open journal segment, write the encrypted archive, record
// its checksum, and resume dispatch. When the Gateway was already in
// emergency stop it stays stopped afterwards.
func (r *Runtime) Backup(req BackupRequest, actor string) (backup.Result, error) {
	enc := backup.Encryption{Passphrase: req.Passphrase, Recipients: req.Recipients, WorkFactor: r.opts.BackupWorkFactor}
	r.opMu.Lock()
	defer r.opMu.Unlock()
	cfg := r.app.Config
	g := r.app.Gateway
	if err := enc.Check(); err != nil {
		if errors.Is(err, backup.ErrUnencrypted) {
			r.commit("refused", "BACKUP_UNENCRYPTED_REFUSED", actor, map[string]any{"kind": "backup"})
		}
		return backup.Result{}, err
	}
	wasStopped := g.Stopped()
	if !wasStopped {
		if err := g.StopDraining(actor, "backup"); err != nil {
			return backup.Result{}, err
		}
	}
	resume := func() {
		if !wasStopped {
			if err := g.ResumeDraining(actor); err != nil {
				r.log.Error("dispatch not resumed after backup", "err", err)
			}
		}
	}
	deadline := time.Now().Add(r.opts.DrainTimeout)
	for g.InFlight() > 0 {
		if time.Now().After(deadline) {
			resume()
			r.commit("failed", "BACKUP_DRAIN_TIMEOUT", actor, map[string]any{"kind": "backup", "in_flight": g.InFlight()})
			return backup.Result{}, errDrain
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := r.app.Journal.Seal(); err != nil {
		resume()
		return backup.Result{}, fmt.Errorf("seal journal: %w", err)
	}
	inst, _ := keys.EnsureInstallationID(cfg.State.Dir)
	res, err := backup.Create(cfg.Backup.Dir, backup.Spec{StateDir: cfg.State.Dir, ConfigPath: r.cfgPath, PolicyPath: cfg.Policy.File,
		Optional: req.Optional, InstallationID: inst, Version: backend.Version, Encryption: enc})
	if err != nil {
		r.commit("failed", "BACKUP_FAILED", actor, map[string]any{"kind": "backup", "error": err.Error()})
		resume()
		return res, err
	}
	r.commit("backup_written", "BACKUP_WRITTEN", actor, map[string]any{"kind": "backup", "path": res.Path, "sha256": res.SHA256, "size": res.Size, "components": res.Manifest.Components})
	resume()
	return res, nil
}

func (r *Runtime) handleReload(w http.ResponseWriter, req *http.Request) {
	res, err := r.Reload(adminapi.Actor(req))
	switch {
	case errors.Is(err, ErrReloadInvalid):
		writeError(w, http.StatusUnprocessableEntity, "CONFIG_INVALID", err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, "reload_failed", err.Error())
	default:
		writeJSON(w, http.StatusOK, res)
	}
}
