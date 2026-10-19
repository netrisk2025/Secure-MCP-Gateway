// Package consoleapi is the console backend of the Management Console &
// Control API (E-24): it serves the embedded single-page console on the
// admin listener under a strict Content-Security-Policy, and registers the
// control API routes the console owns:
//
//	GET  /api/v1/sessions                 active harness sessions (G-11)
//	GET  /api/v1/sessions/principals      principals, clients, Session Approvers
//	GET  /api/v1/sessions/{id}            one session
//	POST /api/v1/sessions/{id}/terminate  {reason}: end a session, audited
//	GET  /api/v1/servers                  configured servers and their state (G-10)
//	GET  /api/v1/servers/{alias}          one server with its tools
//	GET  /api/v1/catalog                  public tool catalog per template
//	GET  /api/v1/audit/events             journal browser with filters and paging
//	GET  /api/v1/audit/events/{id}        one event and the events of its call
//	GET  /api/v1/audit/export             CSV or JSON Lines export, audited
//	GET  /api/v1/audit/verify             last journal verification result
//	POST /api/v1/audit/verify             verify the journal now
//	GET  /api/v1/audit/stream             server-sent events of new evidence
//
// All routes are registered with adminapi.Server.Handle, so they take the
// control API's bearer authentication, Host, Origin and Sec-Fetch-Site
// checks, are Administrator-only and record refused authentication. The
// request and response bodies are documented in docs/api/console.md.
package consoleapi

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/console"
	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Sessions is what the session routes need; *session.Store implements it.
type Sessions interface {
	Active() []*session.Session
	List() []*session.Session // active and suspended
	Get(id string) *session.Session
	Terminate(id string) bool
	Suspend(id string) bool
	Resume(id string) bool
}

// Servers is what the server and catalog routes need; *backend.Registry
// implements it.
type Servers interface {
	Servers() map[string]*backend.Server
	Launcher() pipeline.Launcher
}

// Observable registers evidence observers; *audit.Fanout implements it.
type Observable interface {
	AddObserver(name string, o audit.Observer, queue int)
}

// Deps are the components the console reads.
type Deps struct {
	Admin    *adminapi.Server
	Config   *config.Config
	Sessions Sessions
	Servers  Servers
	Snapshot func() *policy.Snapshot
	// Evidence records the console's own actions (terminate, export,
	// verify). It must be the same recorder the rest of the Gateway uses.
	Evidence audit.Recorder
	// Observe, when set, feeds /api/v1/audit/stream.
	Observe Observable
	// JournalDir and PublicKey locate and verify the evidence journal.
	JournalDir string
	AnchorPath string // default audit.DefaultAnchorPath(JournalDir)
	PublicKey  ed25519.PublicKey
	// Assets is the built console (default console.Dist()).
	Assets fs.FS
	Log    *slog.Logger
	Now    func() time.Time
}

// Console is the registered console backend.
type Console struct {
	d      Deps
	stream *hub

	mu         sync.Mutex
	lastVerify *VerifyResult
	verifying  sync.Mutex
}

// FromApp fills Deps from a started Gateway.
func FromApp(a *app.App) (Deps, error) {
	pub, err := keys.LoadEvidencePublicKey(a.Config.State.Dir)
	if err != nil {
		return Deps{}, err
	}
	return Deps{Admin: a.Admin, Config: a.Config, Sessions: a.Store, Servers: a.Registry, Snapshot: a.Decider.Snapshot,
		Evidence: a.Evidence, Observe: a.Evidence, JournalDir: a.Journal.Dir(), AnchorPath: a.Journal.AnchorPath(), PublicKey: pub}, nil
}

// Attach registers the console on a started Gateway's control API.
func Attach(a *app.App, log *slog.Logger) (*Console, error) {
	d, err := FromApp(a)
	if err != nil {
		return nil, err
	}
	d.Log = log
	return Register(d)
}

// Register adds the console routes and the static console to the control
// API.
func Register(d Deps) (*Console, error) {
	if d.Admin == nil || d.Config == nil || d.Sessions == nil || d.Servers == nil || d.Snapshot == nil || d.Evidence == nil {
		return nil, errors.New("consoleapi: admin, config, sessions, servers, snapshot and evidence are required")
	}
	if d.Assets == nil {
		d.Assets = console.Dist()
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.AnchorPath == "" && d.JournalDir != "" {
		d.AnchorPath = audit.DefaultAnchorPath(d.JournalDir)
	}
	c := &Console{d: d, stream: newHub()}
	if d.Observe != nil {
		d.Observe.AddObserver("console-stream", audit.ObserverFunc(c.stream.publish), 256)
	}
	a := d.Admin
	a.Handle("GET /api/v1/sessions", c.listSessions)
	a.Handle("GET /api/v1/sessions/principals", c.principals)
	a.Handle("GET /api/v1/sessions/{id}", c.getSession)
	a.Handle("POST /api/v1/sessions/{id}/terminate", c.terminateSession)
	a.Handle("POST /api/v1/sessions/{id}/suspend", c.suspendSession(true))
	a.Handle("POST /api/v1/sessions/{id}/resume", c.suspendSession(false))
	a.Handle("GET /api/v1/servers", c.listServers)
	a.Handle("GET /api/v1/servers/{alias}", c.getServer)
	a.Handle("GET /api/v1/catalog", c.catalog)
	a.Handle("GET /api/v1/audit/events", c.listEvents)
	a.Handle("GET /api/v1/audit/events/{id}", c.getEvent)
	a.Handle("GET /api/v1/audit/export", c.export)
	a.Handle("GET /api/v1/audit/verify", c.lastVerification)
	a.Handle("POST /api/v1/audit/verify", c.verifyNow)
	a.Handle("GET /api/v1/audit/stream", c.streamEvents)
	a.Handle("GET /api/v1/decisions/{id}/explanation", c.decisionExplanation)
	c.registerStatic(a)
	return c, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// decode reads a JSON body; an empty body is allowed and leaves v unchanged.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// commit writes an E-24 evidence event; the caller refuses the action when
// it fails.
func (c *Console) commit(r *http.Request, outcome, reason string, ev audit.Event) error {
	ev.Class, ev.Origin, ev.Outcome, ev.ReasonCode, ev.PolicyStatus = "admin", "E-24", outcome, reason, "not_evaluated"
	detail, _ := ev.Detail.(map[string]any)
	if detail == nil {
		detail = map[string]any{}
	}
	detail["actor"] = adminapi.ActorOf(r)
	ev.Detail = detail
	return c.d.Evidence.Commit(ev)
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
