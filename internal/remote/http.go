package remote

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Paths served on the remote listener (FR-16.4). Everything else is 404.
const (
	pathPRM        = "/.well-known/oauth-protected-resource"
	pathASM        = "/.well-known/oauth-authorization-server"
	pathAuthorize  = "/oauth/authorize"
	pathToken      = "/oauth/token"
	pathRegister   = "/oauth/register"
	pathDeviceAuth = "/oauth/device_authorization"
	pathDevice     = "/oauth/device"
)

// Gateway error code for rate limits (Appendix B).
const codeRateLimited = -31005

// Handler returns the remote listener's handler: the FR-16.7 bounds, the
// FR-16.3 host check and the FR-16.4 path set apply before any routing.
func (s *Service) Handler() http.Handler {
	mcpPath := s.cfg.Listener.MCPPath
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+pathPRM, s.protectedResourceMetadata)
	mux.HandleFunc("GET "+pathPRM+mcpPath, s.protectedResourceMetadata)
	mux.HandleFunc("GET "+pathASM, s.authorizationServerMetadata)
	mux.HandleFunc("POST "+pathRegister, s.register)
	mux.HandleFunc("GET "+pathAuthorize, s.authorizeGET)
	mux.HandleFunc("POST "+pathAuthorize, s.authorizePOST)
	mux.HandleFunc("POST "+pathToken, s.token)
	mux.HandleFunc("POST "+pathDeviceAuth, s.deviceAuthorization)
	mux.HandleFunc("GET "+pathDevice, s.deviceGET)
	mux.HandleFunc("POST "+pathDevice, s.devicePOST)
	mux.Handle(mcpPath, http.HandlerFunc(s.serveMCP))
	allowed := map[string]bool{pathPRM: true, pathPRM + mcpPath: true, pathASM: true, pathRegister: true, pathAuthorize: true,
		pathToken: true, pathDeviceAuth: true, pathDevice: true, mcpPath: true}
	limits := s.cfg.Remote.Limits
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !s.lim.acquireTotal() { // CP-49 total concurrency, before parsing
			w.Header().Set("Retry-After", "1")
			http.Error(w, "remote listener busy", http.StatusServiceUnavailable)
			return
		}
		defer s.lim.releaseTotal()
		if headerBytes(r) > limits.HeaderBytes { // FR-16.7
			http.Error(w, "request headers too large", http.StatusRequestHeaderFieldsTooLarge)
			return
		}
		if r.ContentLength > limits.BodyBytes { // FR-16.7
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limits.BodyBytes)
		pub := s.publicURL()
		if pub == "" || !strings.EqualFold(r.Host, publicHost(pub)) { // FR-16.3
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		if !allowed[r.URL.Path] { // FR-16.4
			http.NotFound(w, r)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, pub) && !contains(s.cfg.Listener.AllowedOrigins, o) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		org := channel.Origin{Channel: channel.Remote, ClientAddress: s.clientAddress(r)}
		r = r.WithContext(channel.With(r.Context(), org))
		if r.URL.Path != mcpPath {
			if ok, d := s.lim.allowOAuth(rateKey(org.ClientAddress)); !ok { // FR-16.6
				authguard.RetryAfter(w, d)
				oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "rate limit exceeded")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// headerBytes approximates the size of the request head as received.
func headerBytes(r *http.Request) int {
	n := len(r.Method) + len(r.RequestURI) + len(r.Proto) + 4 + len(r.Host) + 8
	for k, vs := range r.Header {
		for _, v := range vs {
			n += len(k) + len(v) + 4
		}
	}
	return n
}

// clientAddress is the tunnel-supplied caller address (server-asserted,
// FR-16.8), falling back to the TCP peer. For X-Forwarded-For the
// rightmost entry is used: it was appended by the tunnel connector, while
// entries to its left are whatever the caller sent.
func (s *Service) clientAddress(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get(s.cfg.Remote.ClientAddressHeader))
	if strings.EqualFold(s.cfg.Remote.ClientAddressHeader, "X-Forwarded-For") {
		vals := r.Header.Values("X-Forwarded-For")
		if len(vals) > 0 {
			parts := strings.Split(vals[len(vals)-1], ",")
			v = strings.TrimSpace(parts[len(parts)-1])
		}
	}
	if v == "" || net.ParseIP(v) == nil {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if v == "" {
			return host
		}
		// A non-IP value is kept, bounded and printable, so the record
		// shows what the tunnel sent.
		v = strings.Map(func(c rune) rune {
			if c < 0x21 || c > 0x7e {
				return -1
			}
			return c
		}, v)
		if len(v) > 64 {
			v = v[:64]
		}
	}
	return v
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int64, msg, reason string, extra map[string]any) {
	data := map[string]any{"reasonCode": reason, "correlationId": ids.New(), "message": msg}
	for k, v := range extra {
		data[k] = v
	}
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg, "data": data}})
}

// serveMCP applies the per-client limits, then hands the request to the
// Harness Edge with the remote origin in its context. Authentication
// failures are left to the edge so that the 401 and its evidence are the
// same as on the local listener.
func (s *Service) serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.mcp.ServeHTTP(w, r) // the edge answers 405 (FR-1.3)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var head struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(body, &head)
	sess, err := s.store.Authenticate(session.Bearer(r), channel.Remote)
	if err != nil {
		s.mcp.ServeHTTP(w, r)
		return
	}
	if !s.lim.acquireClient(sess.ClientID) {
		w.Header().Set("Retry-After", "1")
		writeRPCError(w, http.StatusTooManyRequests, head.ID, codeRateLimited, "Too many concurrent requests from this client through remote access.", "REMOTE_CONCURRENCY", nil)
		return
	}
	defer s.lim.releaseClient(sess.ClientID)
	if head.Method == "tools/call" {
		if ok, d := s.lim.allowCall(sess.ClientID); !ok { // FR-16.6
			authguard.RetryAfter(w, d)
			writeRPCError(w, http.StatusTooManyRequests, head.ID, codeRateLimited, "Remote tool-call rate limit reached; retry later.", "REMOTE_RATE_LIMITED",
				map[string]any{"callsPerMinute": s.cfg.Remote.Limits.CallsPerMinute})
			return
		}
	}
	s.mcp.ServeHTTP(w, r)
}
