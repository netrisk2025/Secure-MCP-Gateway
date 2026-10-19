package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// catalogSet is the set of public tool names a session server presents. It
// changes in place when a new policy revision is activated, so methodGate
// reads it under a lock.
type catalogSet struct {
	mu       sync.RWMutex
	names    map[string]bool
	revision string // the policy revision the names come from
}

// rev returns the policy revision of the presented names.
func (c *catalogSet) rev() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.revision
}

func (c *catalogSet) has(name string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.names[name]
}

// serverFor returns the session's mcp.Server, building it on first use and
// bringing it to the active revision in place after a revision change
// (SR-5.7-1), so that open listen streams on it receive
// notifications/tools/list_changed. Without a snapshot it returns an empty
// server and caches nothing; mcpChain has already refused the request in
// that state, so this only covers a snapshot removed between the two
// checks.
func (g *Gateway) serverFor(r *http.Request) *mcp.Server {
	sess, _ := r.Context().Value(ctxSession).(*session.Session)
	snap := g.decider.Snapshot()
	if sess == nil || snap == nil {
		return g.emptyServer(nil)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	ss := g.servers[sess.ID]
	if ss != nil && ss.revision == snap.Revision {
		return ss.srv
	}
	if !g.store.IsActive(sess.ID) {
		return g.emptyServer(nil)
	}
	if ss == nil {
		ss = &sessionServer{sess: *sess, catalog: &catalogSet{names: map[string]bool{}}}
		ss.srv = g.emptyServer(ss.catalog)
		g.servers[sess.ID] = ss
	}
	g.syncCatalog(ss, snap)
	return ss.srv
}

// syncCatalogs brings every cached session server to the active revision
// and returns how many changed. ActivatePolicy calls it after the swap; each
// changed server sends notifications/tools/list_changed to its open listen
// streams.
func (g *Gateway) syncCatalogs() int {
	snap := g.decider.Snapshot()
	if snap == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, ss := range g.servers {
		if ss.revision != snap.Revision {
			g.syncCatalog(ss, snap)
			n++
		}
	}
	return n
}

// dropUnresolved removes from every cached session catalog the tools the
// registry no longer resolves, which happens when a server is suspended
// (backend.Registry.OnSuspend). Each changed server sends
// notifications/tools/list_changed to its open listen streams (FR-1.35);
// sessions whose catalog holds none of those tools are not touched.
func (g *Gateway) dropUnresolved() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, ss := range g.servers {
		ss.catalog.mu.Lock()
		var gone []string
		for name := range ss.catalog.names {
			if g.reg.Resolve(name) == nil {
				gone = append(gone, name)
				delete(ss.catalog.names, name)
			}
		}
		ss.catalog.mu.Unlock()
		if len(gone) > 0 {
			ss.srv.RemoveTools(gone...)
			n++
		}
	}
	return n
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

// serverInfo identifies the Gateway in every result (FR-1.15): the SDK
// sets it as _meta.io.modelcontextprotocol/serverInfo on the results it
// writes, and the edge on the results it writes itself.
var serverInfo = &mcp.Implementation{Name: "secure-mcp-gateway", Version: backend.Version}

func (g *Gateway) emptyServer(catalog *catalogSet) *mcp.Server {
	srv := mcp.NewServer(serverInfo, g.serverOptions())
	srv.AddReceivingMiddleware(g.methodGate(catalog))
	return srv
}

// syncCatalog sets the session server's tools to what snap grants the
// session's template (FR-1.26, FR-1.28, FR-1.50, SR-5.4-1): tools no longer
// granted are removed and granted tools are added or replaced. Tool
// definitions come from the registry's ManifestSource: verified manifests
// once E-13 provides them, the live list until then. g.mu must be held.
func (g *Gateway) syncCatalog(ss *sessionServer, snap *policy.Snapshot) {
	type entry struct {
		tool *mcp.Tool
		ref  *backend.ToolRef
	}
	want := map[string]bool{}
	var add []entry
	for _, gr := range snap.Grants(ss.sess.Template) {
		ref := g.reg.Resolve(backend.PublicName(gr.Server, gr.Tool))
		if ref == nil {
			continue // policy names a tool no enabled server provides
		}
		if g.screen != nil && g.screen.Present(context.Background(), ref.Server.Alias, ref.Server.Revision, ref.Tool) != nil {
			continue // FR-1.52: blocked by the active metadata rule set
		}
		if gatewayAdminTool(ref) {
			continue // SR-3.12-1: never presented, whatever the policy grants
		}
		want[ref.Public] = true
		t := &mcp.Tool{
			Name:        ref.Public,
			Title:       ref.Tool.Title,
			Description: ref.Tool.Description,
			InputSchema: stripHeaderAnnotations(ref.Tool.InputSchema),
			Annotations: ref.Tool.Annotations,
			Icons:       presentableIcons(ref.Tool.Icons), // SR-5.18-2
		}
		if ref.Tool.OutputSchema != nil {
			t.OutputSchema = ref.Tool.OutputSchema
		}
		if gr.Rule.Approval { // FR-1.50
			t.Meta = mcp.Meta{MetaRequiresUserInteraction: true, MetaApprovalRequired: true}
		}
		add = append(add, entry{t, ref})
	}
	ss.catalog.mu.Lock()
	var gone []string
	for name := range ss.catalog.names {
		if !want[name] {
			gone = append(gone, name)
		}
	}
	ss.catalog.names = want
	ss.catalog.revision = snap.Revision
	ss.catalog.mu.Unlock()
	if len(gone) > 0 {
		ss.srv.RemoveTools(gone...)
	}
	for _, e := range add {
		ss.srv.AddTool(e.tool, g.toolHandler(ss.sess, e.ref))
	}
	ss.revision = snap.Revision
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
func (g *Gateway) methodGate(catalog *catalogSet) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if !allowedMethods[method] {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not available: " + method}
			}
			if method == "tools/call" {
				if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && !catalog.has(p.Name) {
					return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "Unknown tool"}
				}
			}
			if method == "tools/list" && catalog != nil {
				return g.pagedList(ctx, catalog, next, method, req)
			}
			return next(ctx, method, req)
		}
	}
}
