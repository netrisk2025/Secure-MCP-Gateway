package library

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// RegisterRoutes adds the /api/v1/packages routes to the control API
// (docs/api/packages.md). Every route uses the control API's bearer
// authentication, origin and content-type checks; a successful
// authentication is the Administrator action SR-3.9-1 requires.
func (rt *Runtime) RegisterRoutes(s *adminapi.Server) {
	s.Handle("GET /api/v1/packages", rt.apiList)
	s.Handle("GET /api/v1/packages/receipts", rt.apiReceipts)
	s.Handle("POST /api/v1/packages/scan", rt.apiScan)
	s.Handle("GET /api/v1/packages/{id}/{rev}", rt.apiGet)
	s.Handle("POST /api/v1/packages/{id}/{rev}/enable", rt.apiEnable)
	s.Handle("POST /api/v1/packages/{id}/{rev}/classification", rt.apiOverride)
	s.Handle("POST /api/v1/packages/{id}/{rev}/disable", rt.apiState(StateVerifiedDisabled))
	s.Handle("POST /api/v1/packages/{id}/{rev}/retire", rt.apiState(StateRetired))
	rt.RegisterTrustRoutes(s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	code := packaging.ReasonOf(err)
	status := http.StatusConflict
	switch code {
	case "":
		code, status = "internal_error", http.StatusInternalServerError
	case ReasonUnknown:
		status = http.StatusNotFound
	}
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": err.Error()}})
}

// decodeBody reads an optional JSON object body.
func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

type anchorView struct {
	Name    string   `json:"name"`
	KeyID   string   `json:"key_id"`
	Classes []string `json:"classes"`
	Expires string   `json:"expires"`
}

func (rt *Runtime) apiList(w http.ResponseWriter, r *http.Request) {
	anchors := []anchorView{}
	if a, err := packaging.LoadAnchors(rt.lib.stateDir); err == nil {
		for _, x := range a.Anchors {
			anchors = append(anchors, anchorView{Name: x.Name, KeyID: x.KeyID, Classes: x.Classes, Expires: x.Expires.Format("2006-01-02T15:04:05Z07:00")})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"library": rt.lib.Dir(), "revisions": rt.lib.Revisions(), "servers": rt.Bindings(), "trust_anchors": anchors})
}

func (rt *Runtime) apiGet(w http.ResponseWriter, r *http.Request) {
	id, rev := r.PathValue("id"), r.PathValue("rev")
	if !packaging.ValidID(id, rev) {
		writeErr(w, errf(ReasonUnknown, "no revision %s@%s", id, rev))
		return
	}
	got, ok := rt.lib.Get(id, rev)
	if !ok {
		writeErr(w, errf(ReasonUnknown, "no revision %s@%s", id, rev))
		return
	}
	out := map[string]any{"revision": got}
	for name, file := range map[string]string{"manifest": packaging.ManifestFile, "provenance": packaging.ProvenanceFile} {
		if raw, err := os.ReadFile(filepath.Join(rt.lib.revisionDir(id, rev), file)); err == nil {
			out[name] = json.RawMessage(raw)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (rt *Runtime) apiScan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, rt.Scan(adminapi.Actor(r)))
}

func (rt *Runtime) apiEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Alias string `json:"alias"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "bad_request", "message": "body must be {alias?}"}})
		return
	}
	rt.mu.Lock()
	standalone := rt.standalone
	rt.mu.Unlock()
	got, err := rt.lib.Enable(r.PathValue("id"), r.PathValue("rev"), EnableOptions{Actor: adminapi.Actor(r), Alias: body.Alias, Standalone: standalone})
	if err != nil {
		writeErr(w, err)
		return
	}
	// The backend registry starts servers once; a newly enabled revision
	// runs after the next Gateway start.
	running := false
	for _, b := range rt.Bindings() {
		if b.Package == got.ServerID && b.Revision == got.Revision && b.Status == "running" {
			running = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": got, "restart_required": !running})
}

func (rt *Runtime) apiState(state string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Reason string `json:"reason"`
		}
		if err := decodeBody(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "bad_request", "message": "body must be {reason?}"}})
			return
		}
		if body.Reason == "" {
			body.Reason = "administrator action"
		}
		got, gone, err := rt.lib.SetState(r.PathValue("id"), r.PathValue("rev"), state, body.Reason, adminapi.Actor(r))
		if err != nil {
			writeErr(w, err)
			return
		}
		if gone != "" {
			rt.teardown(gone, state+": "+body.Reason)
		}
		writeJSON(w, http.StatusOK, map[string]any{"revision": got})
	}
}

func (rt *Runtime) apiReceipts(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(rt.lib.path("receipts"))
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > 100 {
		names = names[:100]
	}
	out := make([]json.RawMessage, 0, len(names))
	for _, n := range names {
		if raw, err := os.ReadFile(filepath.Join(rt.lib.path("receipts"), n)); err == nil && json.Valid(raw) {
			out = append(out, raw)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"receipts": out})
}
