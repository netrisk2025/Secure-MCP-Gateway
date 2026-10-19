package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// Router is the part of the control API server (adminapi.Server) that
// registers authenticated routes.
type Router interface {
	Handle(pattern string, h http.HandlerFunc)
}

// API serves the /api/v1/runtime routes. Launcher is nil when the Gateway
// runs without a sandbox (standalone profile); the routes then report that.
type API struct {
	Launcher *Launcher
	// Actor names the authenticated caller (adminapi.Actor).
	Actor func(*http.Request) string
	// Doctor runs the prerequisite checks (default Doctor with defaults).
	Doctor func(ctx context.Context) []Check
}

// Register adds the routes to r.
func (a *API) Register(r Router) {
	if a.Doctor == nil {
		var do DoctorOptions
		if a.Launcher != nil {
			do = DoctorOptionsFor(a.Launcher.o.Runtime)
			do.Podman = a.Launcher.podPath
		}
		a.Doctor = func(ctx context.Context) []Check { return Doctor(ctx, do) }
	}
	if a.Actor == nil {
		a.Actor = func(*http.Request) string { return "" }
	}
	r.Handle("GET /api/v1/runtime", a.summary)
	r.Handle("GET /api/v1/runtime/instances", a.instances)
	r.Handle("GET /api/v1/runtime/instances/{id}", a.instance)
	r.Handle("POST /api/v1/runtime/instances/{id}/kill", a.kill)
	r.Handle("GET /api/v1/runtime/doctor", a.doctor)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (a *API) summary(w http.ResponseWriter, _ *http.Request) {
	if a.Launcher == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sandbox": "none", "launcher": "subprocess", "confined": false, "instances": 0})
		return
	}
	l := a.Launcher
	rt := l.o.Runtime
	counts := map[string]int{}
	for _, v := range l.Instances() {
		counts[v.State]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sandbox": "podman", "launcher": l.Name(), "confined": l.Confined(), "gateway_id": l.gateway, "podman": l.podPath,
		"defaults": map[string]any{"memory_bytes": rt.MemoryBytes, "cpus": rt.CPUs, "pids": rt.Pids, "tmpfs_bytes": rt.TmpfsBytes,
			"nofile": rt.NoFile, "userns_size": rt.UserNSSize, "user": rt.User, "image": rt.Image,
			"monitor_interval": rt.MonitorInterval.String()},
		"instances": counts,
	})
}

func (a *API) instances(w http.ResponseWriter, _ *http.Request) {
	if a.Launcher == nil {
		writeJSON(w, http.StatusOK, map[string]any{"instances": []InstanceView{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"instances": a.Launcher.Instances()})
}

// stderrTail bounds the diagnostic output returned by the control API
// (CP-37 per-call bound).
const stderrTail = 64 << 10

func (a *API) instance(w http.ResponseWriter, r *http.Request) {
	if a.Launcher == nil {
		writeError(w, http.StatusNotFound, "no_instance", "no sandboxed instances: the Gateway runs without a sandbox")
		return
	}
	in, ok := a.Launcher.Instance(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "no_instance", "no instance with that ID")
		return
	}
	tail := in.stderr.Tail()
	if len(tail) > stderrTail {
		tail = tail[len(tail)-stderrTail:]
	}
	writeJSON(w, http.StatusOK, map[string]any{"instance": in.View(), "stderr_tail": tail})
}

func (a *API) kill(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "body must be {reason}")
		return
	}
	if a.Launcher == nil {
		writeError(w, http.StatusNotFound, "no_instance", "no sandboxed instances: the Gateway runs without a sandbox")
		return
	}
	id := r.PathValue("id")
	if err := a.Launcher.Kill(id, a.Actor(r), body.Reason); err != nil {
		if errors.Is(err, ErrNoInstance) {
			writeError(w, http.StatusNotFound, "no_instance", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "kill_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"instance_id": id, "state": StateKilled})
}

func (a *API) doctor(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	checks := a.Doctor(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"ready": len(Failed(checks)) == 0, "checks": checks})
}
