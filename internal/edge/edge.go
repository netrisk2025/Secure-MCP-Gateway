// Package edge is the Harness Edge (E-01 Harness Interface Endpoint, E-02
// Protocol Mediator) together with the slice of the Access Enforcement Point
// (E-08) and Enforcement Coordinator (E-12) that a tool call passes through.
//
// The MCP wire protocol for both eras comes from the MCP Go SDK's
// StreamableHTTPHandler in stateless mode (see spikes/go-sdk-dual-era). One
// mcp.Server exists per Gateway session; it holds exactly the tools the
// session's policy permits (SR-5.4-1, SR-5.7-1) and every call runs the
// pipeline of FR-4.3 in order: authenticate, session check, decision,
// request inspection, (approval), launch authorization, dispatch, response
// validation, provenance, release authorization.
package edge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Appendix B Gateway error codes.
const (
	CodePolicyDenied      = -31001
	CodeApprovalRequired  = -31002
	CodeResponseWithheld  = -31003
	CodeGatewayFailClosed = -31004
	CodeRateLimited       = -31005
	CodeSessionInvalid    = -31006
	CodeBackendError      = -31007
	CodeTimeout           = -31008
	CodeIndeterminate     = -31009
)

// Supported northbound protocol versions (CP-04).
var ProtocolVersions = []string{"2026-07-28", "2025-11-25"}

const metaPrefix = "local.smcpgw/"

// Gateway wires the slice together.
type Gateway struct {
	cfg     *config.Config
	store   *session.Store
	oauth   *session.OAuth
	decider *policy.Decider
	reg     *backend.Registry
	journal *audit.Journal
	log     *slog.Logger

	stopped atomic.Bool // FR-4.14 emergency stop
	mux     *http.ServeMux
	handler *mcp.StreamableHTTPHandler

	mu      sync.Mutex
	servers map[string]*sessionServer

	capMu sync.Mutex
	caps  map[string]launchCap // one-use launch capabilities (FR-4.13)
}

type sessionServer struct {
	sess     *session.Session
	revision string
	srv      *mcp.Server
}

type launchCap struct {
	correlation, decision, revision string
	used                            bool
}

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxCorrelation
)

// New builds the Gateway over already-started components.
func New(cfg *config.Config, store *session.Store, oauth *session.OAuth, decider *policy.Decider, reg *backend.Registry, journal *audit.Journal, log *slog.Logger) *Gateway {
	if log == nil {
		log = slog.Default()
	}
	g := &Gateway{cfg: cfg, store: store, oauth: oauth, decider: decider, reg: reg, journal: journal, log: log,
		servers: map[string]*sessionServer{}, caps: map[string]launchCap{}}
	g.handler = mcp.NewStreamableHTTPHandler(g.serverFor, &mcp.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        true,                        // FR-1.6: JSON unless the request needs a stream
		MaxRequestBodyBytes: cfg.Limits.RequestBodyBytes, // CP-07, before parsing (SR-7.11-1)
		Logger:              log,
	})
	g.mux = http.NewServeMux()
	oauth.Register(g.mux)
	g.mux.Handle(cfg.Listener.MCPPath, g.mcpChain(g.handler))
	g.mux.HandleFunc("GET /healthz", g.healthz)
	store.OnEnd(g.sessionEnded)
	return g
}

// Handler returns the harness listener's HTTP handler (host and origin
// checks apply to every path).
func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.hostAllowed(r) { // SR-2.9-2
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !g.originAllowed(o) { // SR-2.9-1
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		g.mux.ServeHTTP(w, r)
	})
}

func (g *Gateway) hostAllowed(r *http.Request) bool {
	host := r.Host
	if u, err := url.Parse(g.cfg.Listener.PublicURL); err == nil && strings.EqualFold(host, u.Host) {
		return true
	}
	return strings.EqualFold(host, g.cfg.Listener.Address)
}

func (g *Gateway) originAllowed(origin string) bool {
	for _, o := range g.cfg.Listener.AllowedOrigins {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}

// TLSConfig is the SR-2.8-1 profile: TLS 1.3 only.
func TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, nil
}

// Serve runs the TLS listener until ctx ends.
func (g *Gateway) Serve(ctx context.Context) error {
	tc, err := TLSConfig(g.cfg.Listener.TLSCert, g.cfg.Listener.TLSKey)
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(g.cfg.Listener.Address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); (ip == nil && host != "localhost") || (ip != nil && !ip.IsLoopback()) {
		return fmt.Errorf("listener %q is not loopback (SR-2.9-3)", g.cfg.Listener.Address)
	}
	srv := &http.Server{
		Addr:              g.cfg.Listener.Address,
		Handler:           g.Handler(),
		TLSConfig:         tc,
		ReadHeaderTimeout: 5 * time.Second,  // CP-06
		ReadTimeout:       15 * time.Second, // CP-07
		MaxHeaderBytes:    16 << 10,         // CP-06
		ErrorLog:          slog.NewLogLogger(g.log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}

// Stop enters the emergency-stop state (FR-4.14); Resume leaves it.
func (g *Gateway) Stop()   { g.stopped.Store(true) }
func (g *Gateway) Resume() { g.stopped.Store(false) }

// failClosed reports whether MCP requests must be refused (FR-9.17, SR-1.2-1, FR-4.14).
func (g *Gateway) failClosed() bool { return g.stopped.Load() || g.decider.Snapshot() == nil }

func (g *Gateway) healthz(w http.ResponseWriter, r *http.Request) {
	state := "healthy"
	var causes []string
	if g.stopped.Load() {
		state, causes = "fail-closed", append(causes, "emergency_stop")
	}
	if g.decider.Snapshot() == nil {
		state, causes = "fail-closed", append(causes, "no_decision_snapshot")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"state": state, "causes": causes, "sessions": len(g.store.Active()), "version": backend.Version})
}

// gatewayError builds an Appendix B error with FR-1.20 data.
func gatewayError(code int64, msg, reason, correlation, decision string, extra map[string]any) *jsonrpc.Error {
	data := map[string]any{"reasonCode": reason, "correlationId": correlation}
	if decision != "" {
		data["decisionId"] = decision
	}
	for k, v := range extra {
		data[k] = v
	}
	raw, _ := json.Marshal(data)
	return &jsonrpc.Error{Code: code, Message: msg, Data: raw}
}

func writeRPCError(w http.ResponseWriter, status int, e *jsonrpc.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": nil, "error": e})
}

// mcpChain is the E-01/E-03 front of the MCP endpoint.
func (g *Gateway) mcpChain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { // FR-1.3
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		corr := ids.New() // FR-4.2
		if g.failClosed() {
			writeRPCError(w, http.StatusServiceUnavailable, gatewayError(CodeGatewayFailClosed, "gateway fail-closed", "FAIL_CLOSED", corr, "", nil))
			return
		}
		sess, err := g.store.Authenticate(session.Bearer(r), "tls") // FR-2.5, SR-2.1-3
		if err != nil {
			g.record(audit.Event{Class: "auth_failure", Origin: "E-03", CorrelationID: corr, Outcome: "deny", ReasonCode: "SESSION_INVALID", PolicyStatus: "not_evaluated"})
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, g.oauth.ResourceMetadataURL()))
			writeRPCError(w, http.StatusUnauthorized, gatewayError(CodeSessionInvalid, "session invalid", "SESSION_INVALID", corr, "", nil))
			return
		}
		ctx := context.WithValue(r.Context(), ctxSession, sess)
		ctx = context.WithValue(ctx, ctxCorrelation, corr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (g *Gateway) record(ev audit.Event) {
	if g.journal == nil {
		return
	}
	if err := g.journal.Record(ev); err != nil {
		g.log.Error("audit record failed", "err", err)
	}
}

// serverFor returns the session's mcp.Server, building it on first use or
// after a policy revision change (SR-5.7-1).
func (g *Gateway) serverFor(r *http.Request) *mcp.Server {
	sess, _ := r.Context().Value(ctxSession).(*session.Session)
	if sess == nil {
		return g.emptyServer(nil)
	}
	snap := g.decider.Snapshot()
	g.mu.Lock()
	defer g.mu.Unlock()
	if ss := g.servers[sess.ID]; ss != nil && snap != nil && ss.revision == snap.Revision {
		return ss.srv
	}
	srv := g.buildServer(sess, snap)
	g.servers[sess.ID] = &sessionServer{sess: sess, revision: snap.Revision, srv: srv}
	return srv
}

func (g *Gateway) serverOptions() *mcp.ServerOptions {
	return &mcp.ServerOptions{
		SupportedProtocolVersions: ProtocolVersions,
		PageSize:                  g.cfg.Limits.CatalogPageSize, // CP-19
		Capabilities:              &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: true}},
		SetCacheable: func(ctx context.Context, req mcp.Request, c *mcp.Cacheable) { // FR-1.13
			c.TTLMs = g.cfg.Limits.CatalogTTLMs
			c.CacheScope = "private"
		},
		Logger: g.log,
	}
}

func (g *Gateway) emptyServer(catalog map[string]bool) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "secure-mcp-gateway", Version: backend.Version}, g.serverOptions())
	srv.AddReceivingMiddleware(g.methodGate(catalog))
	return srv
}

// buildServer creates the per-session catalog (FR-1.26, FR-1.27, FR-1.28,
// FR-1.50, SR-5.4-1).
func (g *Gateway) buildServer(sess *session.Session, snap *policy.Snapshot) *mcp.Server {
	catalog := map[string]bool{}
	srv := g.emptyServer(catalog)
	if snap == nil {
		return srv
	}
	for _, gr := range snap.Grants(sess.Template) {
		ref := g.reg.Resolve(backend.PublicName(gr.Server, gr.Tool))
		if ref == nil {
			continue // policy names a tool no enabled server provides
		}
		catalog[ref.Public] = true
		t := &mcp.Tool{
			Name:        ref.Public,
			Title:       ref.Tool.Title,
			Description: ref.Tool.Description,
			InputSchema: stripHeaderAnnotations(ref.Tool.InputSchema),
			Annotations: ref.Tool.Annotations,
		}
		if ref.Tool.OutputSchema != nil {
			t.OutputSchema = ref.Tool.OutputSchema
		}
		if gr.Rule.Approval { // FR-1.50
			t.Meta = mcp.Meta{"anthropic/requiresUserInteraction": true}
		}
		srv.AddTool(t, g.toolHandler(sess, ref))
	}
	return srv
}

// stripHeaderAnnotations removes x-mcp-header from a presented schema (FR-1.28).
func stripHeaderAnnotations(schema any) any {
	raw, err := json.Marshal(schema)
	if err != nil {
		return schema
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return schema
	}
	if props, ok := m["properties"].(map[string]any); ok {
		for _, p := range props {
			if pm, ok := p.(map[string]any); ok {
				delete(pm, "x-mcp-header")
			}
		}
	}
	return m
}

// Northbound methods of the baseline profile (FR-1.11) plus the legacy
// handshake (FR-1.46) and ping.
var allowedMethods = map[string]bool{
	"server/discover": true, "tools/list": true, "tools/call": true, "subscriptions/listen": true,
	"initialize": true, "notifications/initialized": true, "ping": true, "notifications/cancelled": true,
}

// methodGate rejects unqualified methods (FR-1.10, FR-1.42) and answers a
// call to a tool outside the session catalog with the FR-1.30 message.
func (g *Gateway) methodGate(catalog map[string]bool) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if !allowedMethods[method] {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not available: " + method}
			}
			if method == "tools/call" {
				if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && !catalog[p.Name] {
					return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "Unknown tool"}
				}
			}
			return next(ctx, method, req)
		}
	}
}

// toolHandler is the per-call enforcement pipeline (FR-4.3).
func (g *Gateway) toolHandler(sess *session.Session, ref *backend.ToolRef) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		corr, _ := ctx.Value(ctxCorrelation).(string)
		if corr == "" {
			corr = ids.New()
		}
		base := audit.Event{CorrelationID: corr, SessionID: sess.ID, PrincipalID: sess.PrincipalID, ServerRevision: ref.Server.Revision, ToolRevision: ref.Revision}
		ev := func(class string, phase audit.Phase, origin, outcome, reason, decision, revision, status string) {
			e := base
			e.Class, e.Phase, e.Origin, e.Outcome, e.ReasonCode, e.DecisionID, e.PolicyRevision, e.PolicyStatus = class, phase, origin, outcome, reason, decision, revision, status
			g.record(e)
		}
		ev("call", audit.PhaseRequested, "E-02", "", "", "", "", "not_evaluated")

		// Session check (the request was authenticated; the session may have
		// ended since the server object was built).
		if cur := g.store.Get(sess.ID); cur == nil || cur.State != session.StateActive {
			ev("call", audit.PhaseDenied, "E-04", "deny", "SESSION_STATE", "", "", "not_evaluated")
			return nil, gatewayError(CodeSessionInvalid, "session invalid", "SESSION_STATE", corr, "", nil)
		}
		if g.failClosed() {
			ev("call", audit.PhaseDenied, "E-12", "deny", "FAIL_CLOSED", "", "", "unavailable")
			return nil, gatewayError(CodeGatewayFailClosed, "gateway fail-closed", "FAIL_CLOSED", corr, "", nil)
		}

		// Decision (SR-5.5-1: every call is evaluated).
		dec := g.decider.Decide(policy.Request{PrincipalID: sess.PrincipalID, SessionID: sess.ID, Template: sess.Template, Server: ref.Server.Alias, Tool: ref.Tool.Name})
		base.DecisionID, base.PolicyRevision = dec.ID, dec.PolicyRevision
		if dec.Outcome != policy.Permit {
			ev("decision", audit.PhaseDenied, "E-06", "deny", dec.ReasonCode, dec.ID, dec.PolicyRevision, "evaluated")
			if dec.ReasonCode == policy.ReasonRateLimited {
				return nil, gatewayError(CodeRateLimited, "rate limited", dec.ReasonCode, corr, dec.ID, map[string]any{"callsPerMinute": dec.Obligations.CallsPerMinute})
			}
			if dec.ReasonCode == policy.ReasonNoSnapshot {
				return nil, gatewayError(CodeGatewayFailClosed, "gateway fail-closed", dec.ReasonCode, corr, dec.ID, nil)
			}
			return nil, gatewayError(CodePolicyDenied, "policy denied", dec.ReasonCode, corr, dec.ID, map[string]any{"decisiveRules": dec.DecisiveRules})
		}

		// Request inspection: schema-validate (FR-4.5 subset).
		args := req.Params.Arguments
		if findings := validateArguments(ref.Tool.InputSchema, args); findings != "" {
			ev("filter", audit.PhaseFiltered, "E-09", "block", "SCHEMA_INVALID", dec.ID, dec.PolicyRevision, "evaluated")
			raw, _ := json.Marshal(map[string]any{"reasonCode": "SCHEMA_INVALID", "correlationId": corr, "decisionId": dec.ID, "findings": findings})
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "arguments do not match the tool schema", Data: raw}
		}

		// Approval obligation: the Approval Service (E-07) is not in this slice,
		// so an approval-obligated call cannot proceed (FR-3.14 without an
		// approval record).
		if dec.Obligations.Approval {
			ev("decision", audit.PhaseDenied, "E-07", "deny", "APPROVAL_REQUIRED", dec.ID, dec.PolicyRevision, "evaluated")
			return nil, gatewayError(CodeApprovalRequired, "approval required", "APPROVAL_REQUIRED", corr, dec.ID, nil)
		}

		// Launch authorization under the barrier (FR-4.13, SR-1.17-1): intent
		// is recorded before the capability is issued (SR-6.2-1 analogue).
		capID, err := g.authorizeLaunch(sess, dec)
		if err != nil {
			ev("call", audit.PhaseDenied, "E-12", "deny", err.Error(), dec.ID, dec.PolicyRevision, "evaluated")
			return nil, gatewayError(CodeGatewayFailClosed, "launch refused", err.Error(), corr, dec.ID, nil)
		}
		ev("decision", audit.PhaseAuthorized, "E-12", "permit", dec.ReasonCode, dec.ID, dec.PolicyRevision, "evaluated")

		// Dispatch (FR-4.8, FR-4.9, FR-4.10) with the one-use capability.
		if !g.consumeCapability(capID, corr) {
			return nil, gatewayError(CodeGatewayFailClosed, "launch capability invalid", "CAPABILITY", corr, dec.ID, nil)
		}
		ev("call", audit.PhaseDispatched, "E-10", "", "", dec.ID, dec.PolicyRevision, "evaluated")
		cctx, cancel := context.WithTimeout(ctx, g.cfg.Limits.ClientDeadline.Duration) // CP-13 client deadline (FR-1.43)
		defer cancel()
		res, err := g.reg.Call(cctx, sess.PrincipalID, ref, req.Params.Arguments, nil)
		if err != nil {
			return nil, g.mapDispatchError(err, corr, dec, ev)
		}

		// Response inspection slice (FR-4.11 disposition, FR-4.12 provenance,
		// SR-5.13-1) and release authorization (SR-1.17-2).
		if res.Meta == nil {
			res.Meta = mcp.Meta{}
		}
		res.Meta[metaPrefix+"provenance"] = map[string]any{
			"serverId": ref.Server.Alias, "serverRevision": ref.Server.Revision, "toolRevision": ref.Revision,
			"decisionId": dec.ID, "filters": []string{"schema-validate", "size-limit"}, "untrusted": true,
		}
		if err := g.authorizeRelease(sess); err != nil {
			ev("call", audit.PhaseWithheld, "E-12", "withhold", err.Error(), dec.ID, dec.PolicyRevision, "evaluated")
			return nil, gatewayError(CodeResponseWithheld, "response withheld", err.Error(), corr, dec.ID, nil)
		}
		outcome := "ok"
		if res.IsError {
			outcome = "tool_error"
		}
		ev("call", audit.PhaseCompleted, "E-10", outcome, "", dec.ID, dec.PolicyRevision, "evaluated")
		ev("call", audit.PhaseDelivered, "E-12", "release", "", dec.ID, dec.PolicyRevision, "evaluated")
		return res, nil
	}
}

func (g *Gateway) mapDispatchError(err error, corr string, dec policy.Decision, ev func(string, audit.Phase, string, string, string, string, string, string)) error {
	var be *backend.BackendError
	switch {
	case errors.As(err, &be): // FR-1.32
		ev("call", audit.PhaseFailed, "E-10", "backend_error", "BACKEND_ERROR", dec.ID, dec.PolicyRevision, "evaluated")
		return gatewayError(CodeBackendError, "backend error", "BACKEND_ERROR", corr, dec.ID, map[string]any{"backendCode": be.Code})
	case errors.Is(err, backend.ErrQueueFull):
		ev("call", audit.PhaseDenied, "E-10", "deny", "QUEUE_FULL", dec.ID, dec.PolicyRevision, "evaluated")
		return gatewayError(CodeRateLimited, "dispatch queue full", "QUEUE_FULL", corr, dec.ID, nil)
	case errors.Is(err, backend.ErrTimeout):
		ev("call", audit.PhaseIndeterminate, "E-10", "timeout", "UPSTREAM_TIMEOUT", dec.ID, dec.PolicyRevision, "evaluated")
		return gatewayError(CodeTimeout, "upstream timeout", "UPSTREAM_TIMEOUT", corr, dec.ID, nil)
	case errors.Is(err, backend.ErrTooLarge):
		ev("call", audit.PhaseWithheld, "E-11", "withhold", "RESULT_TOO_LARGE", dec.ID, dec.PolicyRevision, "evaluated")
		return gatewayError(CodeResponseWithheld, "response withheld", "RESULT_TOO_LARGE", corr, dec.ID, nil)
	case errors.Is(err, context.DeadlineExceeded):
		ev("call", audit.PhaseIndeterminate, "E-10", "timeout", "CLIENT_DEADLINE", dec.ID, dec.PolicyRevision, "evaluated")
		return gatewayError(CodeTimeout, "client deadline expired", "CLIENT_DEADLINE", corr, dec.ID, nil)
	}
	var we *jsonrpc.Error
	if errors.As(err, &we) {
		return we
	}
	ev("call", audit.PhaseFailed, "E-10", "failed", "DISPATCH_FAILED", dec.ID, dec.PolicyRevision, "evaluated")
	return gatewayError(CodeBackendError, "dispatch failed", "DISPATCH_FAILED", corr, dec.ID, nil)
}

// authorizeLaunch rechecks state under the gate and issues a capability.
func (g *Gateway) authorizeLaunch(sess *session.Session, dec policy.Decision) (string, error) {
	g.capMu.Lock()
	defer g.capMu.Unlock()
	if g.stopped.Load() {
		return "", errors.New("EMERGENCY_STOP")
	}
	snap := g.decider.Snapshot()
	if snap == nil || snap.Revision != dec.PolicyRevision {
		return "", errors.New("POLICY_REVISION_CHANGED")
	}
	if cur := g.store.Get(sess.ID); cur == nil || cur.State != session.StateActive {
		return "", errors.New("SESSION_STATE")
	}
	id := ids.Secret()
	g.caps[id] = launchCap{correlation: "", decision: dec.ID, revision: dec.PolicyRevision}
	return id, nil
}

func (g *Gateway) consumeCapability(id, corr string) bool {
	g.capMu.Lock()
	defer g.capMu.Unlock()
	c, ok := g.caps[id]
	if !ok || c.used {
		return false
	}
	delete(g.caps, id)
	return true
}

func (g *Gateway) authorizeRelease(sess *session.Session) error {
	if g.stopped.Load() {
		return errors.New("EMERGENCY_STOP")
	}
	if cur := g.store.Get(sess.ID); cur == nil || cur.State != session.StateActive {
		return errors.New("SESSION_STATE")
	}
	return nil
}

// sessionEnded drops the session's server and closes its MCP sessions, which
// ends any open listen streams (FR-2.11).
func (g *Gateway) sessionEnded(s *session.Session) {
	g.mu.Lock()
	ss := g.servers[s.ID]
	delete(g.servers, s.ID)
	g.mu.Unlock()
	if ss == nil {
		return
	}
	for ms := range ss.srv.Sessions() {
		_ = ms.Close()
	}
	g.record(audit.Event{Class: "session", Origin: "E-04", SessionID: s.ID, PrincipalID: s.PrincipalID, Outcome: s.State, ReasonCode: "SESSION_END", PolicyStatus: "not_evaluated"})
}

// Close releases resources.
func (g *Gateway) Close() {
	g.mu.Lock()
	servers := g.servers
	g.servers = map[string]*sessionServer{}
	g.mu.Unlock()
	for _, ss := range servers {
		for ms := range ss.srv.Sessions() {
			_ = ms.Close()
		}
	}
}
