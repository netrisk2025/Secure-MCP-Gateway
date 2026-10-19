package library

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Trust anchor enrollment on the control API (FR-8.18 trust-anchor
// actions, FR-14.8): the control API form of `smcpctl trust add` and
// `smcpctl trust remove`. Enrollment is Administrator-only (Appendix C).
// The anchors file is read at every import, so a new anchor admits
// packages from the next library scan.

// RegisterTrustRoutes adds POST /api/v1/packages/trust and DELETE
// /api/v1/packages/trust/{name} (docs/api/packages.md).
func (rt *Runtime) RegisterTrustRoutes(s *adminapi.Server) {
	s.Handle("POST /api/v1/packages/trust", rt.apiTrustAdd)
	s.Handle("DELETE /api/v1/packages/trust/{name}", rt.apiTrustRemove)
}

func trustError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (rt *Runtime) apiTrustAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string   `json:"name"`
		PublicKey    string   `json:"public_key"`
		Classes      []string `json:"classes"`
		Expires      string   `json:"expires"`
		Preview      bool     `json:"preview"`
		ConfirmKeyID string   `json:"confirm_key_id"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		trustError(w, http.StatusBadRequest, "bad_request", "body must be {name, public_key, classes, expires, preview, confirm_key_id}")
		return
	}
	// FR-7.10: the key is enrolled only after the administrator confirmed
	// its displayed fingerprint. A preview returns the fingerprint and
	// changes nothing; an enrollment must name the confirmed key ID.
	keyID, sha, err := packaging.Fingerprint([]byte(body.PublicKey))
	if err != nil {
		trustError(w, http.StatusBadRequest, "invalid_anchor", err.Error())
		return
	}
	if body.Preview {
		writeJSON(w, http.StatusOK, map[string]any{"key_id": keyID, "sha256": sha, "name": body.Name, "classes": body.Classes, "expires": body.Expires})
		return
	}
	switch {
	case body.ConfirmKeyID == "":
		trustError(w, http.StatusBadRequest, "confirmation_required", "compare the key fingerprint "+keyID+" with the publisher's and send it as confirm_key_id")
		return
	case !strings.EqualFold(strings.TrimSpace(body.ConfirmKeyID), keyID):
		trustError(w, http.StatusBadRequest, "fingerprint_mismatch", "the confirmed key ID "+body.ConfirmKeyID+" is not the key's fingerprint "+keyID)
		return
	}
	now := time.Now()
	exp := now.Add(365 * 24 * time.Hour)
	if body.Expires != "" {
		t, err := time.Parse(time.RFC3339, body.Expires)
		if err != nil {
			if t, err = time.Parse("2006-01-02", body.Expires); err != nil {
				trustError(w, http.StatusBadRequest, "bad_request", "expires must be a date (2027-10-16) or an RFC 3339 time")
				return
			}
			t = t.Add(24 * time.Hour)
		}
		exp = t
	}
	actor := adminapi.Actor(r)
	rt.trustMu.Lock()
	defer rt.trustMu.Unlock()
	a, err := packaging.LoadAnchors(rt.lib.stateDir)
	if err != nil {
		trustError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	an, err := a.Add(body.Name, []byte(body.PublicKey), body.Classes, exp, now, actor)
	if err != nil {
		trustError(w, http.StatusBadRequest, "invalid_anchor", err.Error())
		return
	}
	if err := rt.lib.evidence(audit.Event{Origin: "E-13", Outcome: "anchor_enrolled", ReasonCode: "TRUST_ANCHOR_ENROLLED",
		Detail: map[string]any{"actor": actor, "anchor": an.Name, "key_id": an.KeyID, "sha256": sha, "fingerprint_confirmed": true, "classes": an.Classes, "expires": an.Expires.Format(time.RFC3339)}}); err != nil {
		trustError(w, http.StatusServiceUnavailable, "audit_unavailable", "evidence journal unavailable; the anchor was not enrolled")
		return
	}
	if err := a.Save(); err != nil {
		trustError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, anchorView{Name: an.Name, KeyID: an.KeyID, Classes: an.Classes, Expires: an.Expires.Format(time.RFC3339)})
}

func (rt *Runtime) apiTrustRemove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	actor := adminapi.Actor(r)
	rt.trustMu.Lock()
	defer rt.trustMu.Unlock()
	a, err := packaging.LoadAnchors(rt.lib.stateDir)
	if err != nil {
		trustError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	if !a.Remove(name) {
		trustError(w, http.StatusNotFound, "not_found", "no trust anchor with that name or key ID")
		return
	}
	if err := rt.lib.evidence(audit.Event{Origin: "E-13", Outcome: "anchor_removed", ReasonCode: "TRUST_ANCHOR_REMOVED", Detail: map[string]any{"actor": actor, "anchor": name}}); err != nil {
		trustError(w, http.StatusServiceUnavailable, "audit_unavailable", "evidence journal unavailable; the anchor was not removed")
		return
	}
	if err := a.Save(); err != nil {
		trustError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"removed": name})
}
