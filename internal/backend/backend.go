// Package backend is the slice of the Local Server Registry (E-14), Server
// Runtime Manager (E-15) and Tool Dispatcher (E-10): it launches each
// configured MCP server as a stdio subprocess through the MCP Go SDK client,
// records its live tool list as the server revision, derives public tool
// names (FR-1.26, FR-1.49, FR-5.22) and dispatches calls with the CP-10
// concurrency bounds (FR-4.8), the CP-13 upstream timeout (FR-4.9), complete
// buffering (FR-4.10) and backend error mapping (FR-1.32).
//
// Not in this slice: signed packages and manifests (E-13), sandboxing
// (E-16), runtime monitoring (E-17) and egress brokering (E-18). Instances
// are shared (one per server), not per session.
package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// Limits are the CP values the dispatcher enforces.
type Limits struct {
	PerPrincipal    int
	Total           int
	Queue           int
	UpstreamTimeout time.Duration
	ResultBytes     int64
	StderrBytes     int
}

// Server is one launched backend instance with its recorded revision.
type Server struct {
	Alias    string
	Revision string // "live-" + first 16 hex of the SHA-256 of the tool list
	Era      string // "2026-07-28" or "2025-11-25" as negotiated by the SDK client
	Tools    []*mcp.Tool
	cfg      config.Server
	session  *mcp.ClientSession
	cmd      *exec.Cmd
	stderr   *ring
}

// ToolRef resolves a public name to its backend (FR-1.29).
type ToolRef struct {
	Public   string
	Server   *Server
	Tool     *mcp.Tool
	Revision string // tool revision: server revision + "/" + tool name
}

// Registry holds launched servers and the public-name index.
type Registry struct {
	limits  Limits
	servers map[string]*Server
	tools   map[string]*ToolRef
	public  []string

	mu       sync.Mutex
	perPrinc map[string]chan struct{}
	total    chan struct{}
	waiting  atomic.Int64
	inFlight sync.WaitGroup
}

var publicPart = regexp.MustCompile(`[^A-Za-z0-9_]`)

// PublicName derives the CP-42 public name (FR-1.26).
func PublicName(alias, tool string) string {
	return alias + "_" + publicPart.ReplaceAllString(tool, "_")
}

var propName = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

// CheckToolDefinition applies the FR-5.22 drift rules to a live tool.
func CheckToolDefinition(t *mcp.Tool) error {
	if t.InputSchema == nil {
		return errors.New("inputSchema is null")
	}
	raw, err := json.Marshal(t.InputSchema)
	if err != nil {
		return fmt.Errorf("inputSchema not serializable: %w", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return errors.New("inputSchema is not an object")
	}
	if props, ok := schema["properties"].(map[string]any); ok {
		for name := range props {
			if !propName.MatchString(name) {
				return fmt.Errorf("property name %q outside 1-64 characters of [A-Za-z0-9_.-]", name)
			}
		}
	}
	return nil
}

// Start launches every configured server and indexes its tools. Any server
// whose tool set cannot be presented (collision, over-long name, invalid
// definition) fails startup with the reason; the Gateway does not run with a
// partially enabled catalog in this slice.
func Start(ctx context.Context, servers []config.Server, limits Limits) (*Registry, error) {
	if limits.StderrBytes <= 0 {
		limits.StderrBytes = 1 << 20
	}
	r := &Registry{limits: limits, servers: map[string]*Server{}, tools: map[string]*ToolRef{}, perPrinc: map[string]chan struct{}{}, total: make(chan struct{}, limits.Total)}
	for _, sc := range servers {
		s, err := launch(ctx, sc, limits)
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("server %q: %w", sc.Alias, err)
		}
		r.servers[s.Alias] = s
		seen := map[string]string{} // public -> backend name
		for _, t := range s.Tools {
			if err := CheckToolDefinition(t); err != nil {
				r.Close()
				return nil, fmt.Errorf("server %q tool %q: drift: %w", sc.Alias, t.Name, err)
			}
			pub := PublicName(s.Alias, t.Name)
			if len(pub) > 64 {
				r.Close()
				return nil, fmt.Errorf("server %q tool %q: public name %q exceeds 64 characters (CP-42)", sc.Alias, t.Name, pub)
			}
			if prev, dup := seen[pub]; dup {
				r.Close()
				return nil, fmt.Errorf("server %q: tools %q and %q both map to public name %q (FR-1.49)", sc.Alias, prev, t.Name, pub)
			}
			seen[pub] = t.Name
			r.tools[pub] = &ToolRef{Public: pub, Server: s, Tool: t, Revision: s.Revision + "/" + t.Name}
			r.public = append(r.public, pub)
		}
	}
	sort.Strings(r.public)
	return r, nil
}

func launch(ctx context.Context, sc config.Server, limits Limits) (*Server, error) {
	cmd := exec.Command(sc.Command, sc.Args...)
	// SR-2.14-1: the instance environment is built from an allowlist, never
	// inherited wholesale. PATH and HOME are needed to run anything at all.
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	for k, v := range sc.Env {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	if sc.Dir != "" {
		cmd.Dir = sc.Dir
	}
	rb := &ring{max: limits.StderrBytes}
	cmd.Stderr = rb
	client := mcp.NewClient(&mcp.Implementation{Name: "secure-mcp-gateway", Version: Version}, nil)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	sess, err := client.Connect(cctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: 5 * time.Second}, nil)
	if err != nil {
		return nil, fmt.Errorf("launch %s: %w (stderr: %s)", sc.Command, err, rb.tail())
	}
	s := &Server{Alias: sc.Alias, cfg: sc, session: sess, cmd: cmd, stderr: rb}
	if ir := sess.InitializeResult(); ir != nil && ir.ProtocolVersion != "" {
		s.Era = ir.ProtocolVersion
	}
	// FR-5.21: the complete tool list across all pages.
	var tools []*mcp.Tool
	for t, err := range sess.Tools(cctx, nil) {
		if err != nil {
			sess.Close()
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		tools = append(tools, t)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	s.Tools = tools
	raw, _ := json.Marshal(tools)
	sum := sha256.Sum256(raw)
	s.Revision = "live-" + hex.EncodeToString(sum[:8])
	return s, nil
}

// Version is the Gateway release version string presented as clientInfo
// and serverInfo. Set by the build.
var Version = "0.0.0-dev"

// Resolve maps a public name to its backend tool.
func (r *Registry) Resolve(public string) *ToolRef { return r.tools[public] }

// PublicNames returns every public name in ascending order (FR-1.25).
func (r *Registry) PublicNames() []string { return append([]string(nil), r.public...) }

// Servers returns the launched servers by alias.
func (r *Registry) Servers() map[string]*Server { return r.servers }

// Errors from Call.
var (
	ErrQueueFull = errors.New("dispatch queue full")  // -31005
	ErrTimeout   = errors.New("upstream timeout")     // -31008 / indeterminate
	ErrTooLarge  = errors.New("result exceeds bound") // -31003 withhold
)

// BackendError carries a backend JSON-RPC error code without its message
// (FR-1.32).
type BackendError struct{ Code int64 }

func (e *BackendError) Error() string { return fmt.Sprintf("backend error %d", e.Code) }

// Call dispatches one tool call under the concurrency bounds and timeout and
// returns the complete, size-checked result.
func (r *Registry) Call(ctx context.Context, principal string, ref *ToolRef, args json.RawMessage, progressToken any) (*mcp.CallToolResult, error) {
	if r.waiting.Load() >= int64(r.limits.Queue) {
		return nil, ErrQueueFull
	}
	r.waiting.Add(1)
	r.mu.Lock()
	pc := r.perPrinc[principal]
	if pc == nil {
		pc = make(chan struct{}, r.limits.PerPrincipal)
		r.perPrinc[principal] = pc
	}
	r.mu.Unlock()
	select {
	case pc <- struct{}{}:
	case <-ctx.Done():
		r.waiting.Add(-1)
		return nil, ctx.Err()
	}
	defer func() { <-pc }()
	select {
	case r.total <- struct{}{}:
	case <-ctx.Done():
		r.waiting.Add(-1)
		return nil, ctx.Err()
	}
	defer func() { <-r.total }()
	r.waiting.Add(-1)
	r.inFlight.Add(1)
	defer r.inFlight.Done()

	cctx, cancel := context.WithTimeout(ctx, r.limits.UpstreamTimeout)
	defer cancel()
	var a any
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "arguments must be a JSON object"}
		}
	}
	params := &mcp.CallToolParams{Name: ref.Tool.Name, Arguments: a}
	if progressToken != nil {
		params.Meta = mcp.Meta{"progressToken": progressToken}
	}
	res, err := ref.Server.session.CallTool(cctx, params)
	if err != nil {
		var we *jsonrpc.Error
		if errors.As(err, &we) {
			return nil, &BackendError{Code: we.Code}
		}
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, ErrTimeout
		}
		return nil, err
	}
	// FR-4.10: the response is buffered completely by the SDK; bound its
	// expanded size before inspection.
	raw, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > r.limits.ResultBytes {
		return nil, ErrTooLarge
	}
	return res, nil
}

// Stderr returns the bounded diagnostic buffer of a server (FR-5.15).
func (s *Server) Stderr() string { return s.stderr.tail() }

// Close shuts every instance down (FR-5.27 ordering is handled by the SDK's
// CommandTransport: stdin close, wait, terminate).
func (r *Registry) Close() {
	r.inFlight.Wait()
	for _, s := range r.servers {
		if s.session != nil {
			_ = s.session.Close()
		}
	}
}

// ring is a bounded stderr buffer (CP-37).
type ring struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (b *ring) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *ring) tail() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.buf))
}
