package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
)

// OAuth is the local OAuth 2.1 authorization server of FR-2.17 to FR-2.22
// and the session API of FR-2.2, mounted on the harness listener.
//
// Sign-in at the authorization endpoint uses a Session Approver account
// (config [[approver]]), never the administrator account. Every password and
// client-secret check goes through an authguard.Guard: per-source rate
// limit, lockout with backoff, bounded concurrent Argon2id and a dummy
// verification for unknown accounts.
type OAuth struct {
	cfg   *config.Config
	store *Store
	audit audit.Recorder
	guard *authguard.Guard
	now   func() time.Time
	cimd  *cimdFetcher // Client ID Metadata Documents (cimd.go)

	mu    sync.Mutex
	codes map[string]*authCode // keyed by SHA-256 of the code
	// redeemed maps the SHA-256 of a redeemed code to the session it
	// created, until the code would have expired, so that a second
	// redemption revokes that session (OAuth 2.1 section 4.1.3).
	redeemed map[string]redeemedCode
}

type redeemedCode struct {
	sessionID string
	expires   time.Time
}

type authCode struct {
	clientID    string
	principalID string
	redirectURI string
	challenge   string
	claims      Claims
	scope       string
	resource    string
	approver    string
	expires     time.Time
}

const (
	pathPRM       = "/.well-known/oauth-protected-resource"
	pathASM       = "/.well-known/oauth-authorization-server"
	pathAuthorize = "/oauth/authorize"
	pathToken     = "/oauth/token"
	pathSessions  = "/smcp/v1/sessions"
	codeLifetime  = 10 * time.Minute
	maxCodes      = 1024
	listenerTLS   = "tls"
)

// NewOAuth builds the authorization server over the session store. rec is
// the evidence recorder; guard may be nil for the defaults.
func NewOAuth(cfg *config.Config, store *Store, rec audit.Recorder, guard *authguard.Guard) *OAuth {
	if rec == nil {
		rec = &audit.Memory{}
	}
	if guard == nil {
		guard = authguard.New(authguard.Config{})
	}
	o := &OAuth{cfg: cfg, store: store, audit: rec, guard: guard, now: time.Now, codes: map[string]*authCode{}, redeemed: map[string]redeemedCode{}}
	o.cimd = newCIMDFetcher(o.clock)
	return o
}

func (o *OAuth) clock() time.Time { o.mu.Lock(); defer o.mu.Unlock(); return o.now() }

// SetNow replaces the clock (tests).
func (o *OAuth) SetNow(f func() time.Time) { o.mu.Lock(); o.now = f; o.mu.Unlock() }

// Register mounts the endpoints on mux.
func (o *OAuth) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+pathPRM, o.protectedResourceMetadata)
	mux.HandleFunc("GET "+pathPRM+o.cfg.Listener.MCPPath, o.protectedResourceMetadata)
	mux.HandleFunc("GET "+pathASM, o.authorizationServerMetadata)
	mux.HandleFunc("GET "+pathAuthorize, o.authorizeGET)
	mux.HandleFunc("POST "+pathAuthorize, o.authorizePOST)
	mux.HandleFunc("POST "+pathToken, o.token)
	mux.HandleFunc("POST "+pathSessions, o.sessionCreate)
	mux.HandleFunc("GET "+pathSessions+"/{id}", o.sessionGet)
	mux.HandleFunc("DELETE "+pathSessions+"/{id}", o.sessionDelete)
}

// ResourceMetadataURL is advertised in WWW-Authenticate on 401 (RFC 9728).
func (o *OAuth) ResourceMetadataURL() string {
	return o.cfg.Listener.PublicURL + pathPRM + o.cfg.Listener.MCPPath
}

// Prune removes expired authorization codes and stale guard entries.
func (o *OAuth) Prune() {
	o.mu.Lock()
	now := o.now()
	for k, c := range o.codes {
		if now.After(c.expires) {
			delete(o.codes, k)
		}
	}
	for k, c := range o.redeemed {
		if now.After(c.expires) {
			delete(o.redeemed, k)
		}
	}
	o.mu.Unlock()
	o.guard.Prune()
}

// Codes returns the number of outstanding authorization codes (tests).
func (o *OAuth) Codes() int { o.mu.Lock(); defer o.mu.Unlock(); return len(o.codes) }

// Run prunes every interval until ctx ends.
func (o *OAuth) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			o.Prune()
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// guardError answers a request the guard refused.
func guardError(w http.ResponseWriter, d time.Duration, err error) {
	authguard.RetryAfter(w, d)
	switch {
	case errors.Is(err, authguard.ErrBusy):
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "sign-in capacity exhausted; retry shortly")
	default:
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", err.Error())
	}
}

// FR-2.17: protected-resource metadata (RFC 9728).
func (o *OAuth) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource":                 o.cfg.ResourceURI(),
		"authorization_servers":    []string{o.cfg.Listener.PublicURL},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Secure MCP Gateway",
		"scopes_supported":         o.templateScopes(),
	})
}

// templateScopes lists smcp:template:<id> for every template a Framework
// Profile of the active policy offers (CP-41).
func (o *OAuth) templateScopes() []string {
	scopes := []string{}
	if snap := o.store.snapshot(); snap != nil {
		for name := range snap.Profiles {
			for _, t := range snap.Profiles[name].Templates {
				if s := "smcp:template:" + t; !slices.Contains(scopes, s) {
					scopes = append(scopes, s)
				}
			}
		}
	}
	slices.Sort(scopes)
	return scopes
}

// FR-2.17: authorization-server metadata (RFC 8414). Client ID Metadata
// Documents are fetched only for the URLs of the CP-52 allowlist (cimd.go),
// so client_id_metadata_document_supported is advertised only when the
// allowlist has an entry.
func (o *OAuth) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	base := o.cfg.Listener.PublicURL
	scopes := o.templateScopes()
	md := map[string]any{
		"issuer":                                         base,
		"authorization_endpoint":                         base + pathAuthorize,
		"token_endpoint":                                 base + pathToken,
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
		"scopes_supported":                               scopes,
		"smcp_scope_patterns":                            []string{"smcp:template:<id>", "smcp:purpose:<tag>", "smcp:project:<path>", "smcp:user:<claim>"},
		"authorization_response_iss_parameter_supported": true,
	}
	if len(o.cfg.ClientMetadata) > 0 {
		md["client_id_metadata_document_supported"] = true
	}
	writeJSON(w, 200, md)
}

// redirectAllowed matches a redirect URI against the client's registered
// URIs. A registered loopback URI with port "*" matches any port, as native
// clients use an ephemeral loopback port.
func redirectAllowed(c *config.Client, uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.Fragment != "" || u.User != nil {
		return false
	}
	for _, reg := range c.RedirectURIs {
		if reg == uri {
			return true
		}
		// A wildcard port is written ":*"; url.Parse rejects it, so substitute
		// a placeholder and remember that any port matches.
		wildcard := strings.Contains(reg, ":*/") || strings.HasSuffix(reg, ":*")
		ru, err := url.Parse(strings.Replace(reg, ":*", ":0", 1))
		if err != nil {
			continue
		}
		if wildcard && (ru.Hostname() == "localhost" || ru.Hostname() == "127.0.0.1" || ru.Hostname() == "::1") &&
			u.Scheme == ru.Scheme && u.Hostname() == ru.Hostname() && u.Path == ru.Path && u.RawQuery == ru.RawQuery {
			return true
		}
	}
	return false
}

type authorizeParams struct {
	ClientID, RedirectURI, State, Scope, Challenge, Method, Resource, ResponseType string
}

func (o *OAuth) parseAuthorize(ctx context.Context, v url.Values) (authorizeParams, *config.Client, string) {
	p := authorizeParams{
		ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), State: v.Get("state"), Scope: v.Get("scope"),
		Challenge: v.Get("code_challenge"), Method: v.Get("code_challenge_method"), Resource: v.Get("resource"), ResponseType: v.Get("response_type"),
	}
	c, err := o.lookupClient(ctx, p.ClientID)
	if err != nil {
		return p, nil, err.Error()
	}
	if !redirectAllowed(c, p.RedirectURI) {
		return p, nil, "redirect_uri not registered for this client"
	}
	return p, c, ""
}

// redirectError sends an OAuth error to the (validated) redirect URI.
func (o *OAuth) redirectError(w http.ResponseWriter, r *http.Request, p authorizeParams, code, desc string) {
	u, _ := url.Parse(p.RedirectURI)
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	q.Set("iss", o.cfg.Listener.PublicURL)
	if p.State != "" {
		q.Set("state", p.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure MCP Gateway sign-in</title>
<style>body{font:16px system-ui,sans-serif;margin:0;padding:24px;max-width:28rem;margin:auto;color:#111;background:#fafafa}
h1{font-size:1.25rem}label{display:block;margin:12px 0 4px}input{width:100%;box-sizing:border-box;padding:8px;font-size:16px}
button{margin-top:16px;padding:10px 16px;font-size:16px}dl{font-size:14px;background:#fff;padding:12px;border:1px solid #ddd}dt{font-weight:600}dd{margin:0 0 8px;word-break:break-all}.err{color:#a00}</style></head>
<body><h1>Secure MCP Gateway</h1>
<p>A framework instance is asking for a Gateway session. Sign in as a Session Approver to approve it.</p>
<dl><dt>Client</dt><dd>{{.ClientID}}</dd><dt>Principal</dt><dd>{{.Principal}}</dd><dt>Requested template</dt><dd>{{.Template}}</dd><dt>Requested scope</dt><dd>{{if .Scope}}{{.Scope}}{{else}}(default template){{end}}</dd></dl>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Approve and continue</button></form></body></html>`))

// SecurityHeaders are set on every HTML response of the authorization
// endpoint: no framing (clickjacking), no inline script, form posts only to
// this origin, no referrer.
func SecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

func (o *OAuth) renderLogin(w http.ResponseWriter, status int, p authorizeParams, c *config.Client, errMsg string) {
	hidden := map[string]string{
		"client_id": p.ClientID, "redirect_uri": p.RedirectURI, "state": p.State, "scope": p.Scope,
		"code_challenge": p.Challenge, "code_challenge_method": p.Method, "resource": p.Resource, "response_type": p.ResponseType,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	SecurityHeaders(w.Header())
	w.WriteHeader(status)
	_ = loginPage.Execute(w, map[string]any{
		"ClientID": p.ClientID, "Principal": c.Principal, "Template": TemplateLabel(p.Scope), "Scope": p.Scope, "Error": errMsg, "Action": pathAuthorize, "Hidden": hidden,
	})
}

// TemplateLabel names the Session Allow Policy Template a scope requests,
// for the sign-in page (FR-2.23): the smcp:template value, or the
// principal's default when the scope names none.
func TemplateLabel(scope string) string {
	if c, err := ParseScopes(strings.Fields(scope)); err == nil && c.Template != "" {
		return c.Template
	}
	return "(default template of the principal's framework profile)"
}

// FR-2.19: authorization endpoint, step 1 (validate and show sign-in).
func (o *OAuth) authorizeGET(w http.ResponseWriter, r *http.Request) {
	SecurityHeaders(w.Header())
	p, c, bad := o.parseAuthorize(r.Context(), r.URL.Query())
	if bad != "" {
		http.Error(w, bad, http.StatusBadRequest)
		return
	}
	if msg := o.checkAuthorize(p); msg != "" {
		o.redirectError(w, r, p, "invalid_request", msg)
		return
	}
	o.renderLogin(w, http.StatusOK, p, c, "")
}

func (o *OAuth) checkAuthorize(p authorizeParams) string {
	if p.ResponseType != "code" {
		return "response_type must be code"
	}
	if p.Method != "S256" || len(p.Challenge) != 43 {
		return "PKCE S256 code_challenge is required"
	}
	if p.Resource != o.cfg.ResourceURI() {
		return "resource must be " + o.cfg.ResourceURI()
	}
	if _, err := ParseScopes(strings.Fields(p.Scope)); err != nil {
		return err.Error()
	}
	return ""
}

// verifyApprover checks a Session Approver sign-in in constant time with
// respect to whether the username exists.
func (o *OAuth) verifyApprover(ctx context.Context, user, pw string) (bool, error) {
	hash := ""
	for _, a := range o.cfg.SessionApprovers() {
		if authguard.EqualName(a.Username, user) {
			hash = a.PasswordHash
		}
	}
	return o.guard.Verify(ctx, hash, pw)
}

// FR-2.19: authorization endpoint, step 2 (Session Approver sign-in, code
// issue).
func (o *OAuth) authorizePOST(w http.ResponseWriter, r *http.Request) {
	SecurityHeaders(w.Header())
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	p, c, bad := o.parseAuthorize(r.Context(), r.PostForm)
	if bad != "" {
		http.Error(w, bad, http.StatusBadRequest)
		return
	}
	if msg := o.checkAuthorize(p); msg != "" {
		o.redirectError(w, r, p, "invalid_request", msg)
		return
	}
	user, pw := r.PostForm.Get("username"), r.PostForm.Get("password")
	src := authguard.Source(r)
	if d, err := o.guard.Check(src, user); err != nil {
		authguard.RetryAfter(w, d)
		o.renderLogin(w, http.StatusTooManyRequests, p, c, "Too many sign-in attempts. Wait and try again.")
		return
	}
	ok, err := o.verifyApprover(r.Context(), user, pw)
	if err != nil {
		o.renderLogin(w, http.StatusServiceUnavailable, p, c, "Sign-in is busy. Try again in a moment.")
		return
	}
	if !ok {
		o.guard.Failure(src, user)
		_ = o.audit.Commit(audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "deny", ReasonCode: "APPROVER_SIGNIN_FAILED", PolicyStatus: "not_evaluated", Detail: map[string]string{"client_id": p.ClientID}})
		o.renderLogin(w, http.StatusUnauthorized, p, c, "Sign-in failed.")
		return
	}
	o.guard.Success(user)
	claims, _ := ParseScopes(strings.Fields(p.Scope))
	code := ids.Secret()
	o.mu.Lock()
	if len(o.codes) >= maxCodes {
		o.mu.Unlock()
		o.Prune()
		o.mu.Lock()
	}
	if len(o.codes) >= maxCodes {
		o.mu.Unlock()
		o.redirectError(w, r, p, "temporarily_unavailable", "too many outstanding authorization codes")
		return
	}
	o.codes[hash(code)] = &authCode{clientID: c.ClientID, principalID: c.Principal, redirectURI: p.RedirectURI, challenge: p.Challenge,
		claims: claims, scope: p.Scope, resource: p.Resource, approver: user, expires: o.now().Add(codeLifetime)}
	o.mu.Unlock()
	u, _ := url.Parse(p.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	q.Set("iss", o.cfg.Listener.PublicURL)
	if p.State != "" {
		q.Set("state", p.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// clientAuth resolves and authenticates the client of a token request
// (client_secret_basic, client_secret_post, or none for public clients).
// Unknown clients cost the same as a wrong secret.
func (o *OAuth) clientAuth(r *http.Request) (*config.Client, int, string) {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		id, secret = u, p
	}
	src := authguard.Source(r)
	if _, err := o.guard.Check(src, "client:"+id); err != nil {
		return nil, http.StatusTooManyRequests, err.Error()
	}
	c, _ := o.lookupClient(r.Context(), id)
	if c == nil {
		if secret != "" {
			_, _ = o.guard.Verify(r.Context(), "", secret)
		}
		o.guard.Failure(src, "client:"+id)
		return nil, http.StatusUnauthorized, "client authentication failed"
	}
	if c.ClientSecretHash != "" {
		ok, err := o.guard.Verify(r.Context(), c.ClientSecretHash, secret)
		if err != nil {
			return nil, http.StatusServiceUnavailable, "authentication capacity exhausted"
		}
		if !ok {
			o.guard.Failure(src, "client:"+id)
			return nil, http.StatusUnauthorized, "client authentication failed"
		}
	}
	return c, 0, ""
}

func pkceOK(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// FR-2.20, FR-2.22: the token endpoint creates or refreshes the session.
func (o *OAuth) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "bad form")
		return
	}
	c, status, bad := o.clientAuth(r)
	if bad != "" {
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="smcp"`)
			_ = o.audit.Commit(audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "deny", ReasonCode: "CLIENT_AUTH_FAILED", PolicyStatus: "not_evaluated"})
			oauthError(w, status, "invalid_client", bad)
		} else {
			authguard.RetryAfter(w, time.Minute)
			oauthError(w, status, "temporarily_unavailable", bad)
		}
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		o.mu.Lock()
		key := hash(r.PostForm.Get("code"))
		ac := o.codes[key]
		delete(o.codes, key) // one use, even when the redemption below fails
		reused, wasRedeemed := o.redeemed[key]
		now := o.now()
		o.mu.Unlock()
		if ac == nil && wasRedeemed && now.Before(reused.expires) {
			o.revokeReused(reused.sessionID, c.ClientID)
			oauthError(w, 400, "invalid_grant", "authorization code already used; the session it created has been revoked")
			return
		}
		switch {
		case ac == nil || now.After(ac.expires) || ac.clientID != c.ClientID:
			oauthError(w, 400, "invalid_grant", "code unknown, expired or issued to another client")
			return
		case ac.redirectURI != r.PostForm.Get("redirect_uri"):
			oauthError(w, 400, "invalid_grant", "redirect_uri mismatch")
			return
		case !pkceOK(r.PostForm.Get("code_verifier"), ac.challenge):
			oauthError(w, 400, "invalid_grant", "PKCE verification failed")
			return
		}
		if res := r.PostForm.Get("resource"); res != "" && res != ac.resource {
			oauthError(w, 400, "invalid_target", "resource mismatch")
			return
		}
		// FR-2.3: the harness may name its type and version on the token
		// request (extension parameters; RFC 6749 section 3.2).
		sess, tok, err := o.store.Create(CreateParams{PrincipalID: ac.principalID, ClientID: c.ClientID, Claims: ac.claims, ApprovedBy: ac.approver, Listener: listenerTLS,
			HarnessType: r.PostForm.Get("harness_type"), HarnessVersion: r.PostForm.Get("harness_version")})
		if err != nil {
			o.sessionError(w, err)
			return
		}
		if !o.recordCreated(w, sess, "OAUTH_CODE", c.ClientID) {
			return
		}
		o.mu.Lock()
		if len(o.redeemed) < maxCodes {
			o.redeemed[key] = redeemedCode{sessionID: sess.ID, expires: ac.expires}
		}
		o.mu.Unlock()
		writeJSON(w, 200, o.tokenResponse(sess, tok))
	case "refresh_token":
		sess, tok, err := o.store.Refresh(r.PostForm.Get("refresh_token"), c.ClientID)
		if errors.Is(err, ErrRefreshReuse) {
			_ = o.audit.Commit(audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, Outcome: StateTerminated, ReasonCode: EndRefreshReuse, PolicyStatus: "not_evaluated", Detail: map[string]string{"client_id": c.ClientID}})
			oauthError(w, 400, "invalid_grant", "refresh token reuse detected; the session has been revoked")
			return
		}
		if err != nil {
			oauthError(w, 400, "invalid_grant", "refresh token invalid, issued to another client or session ended")
			return
		}
		if err := o.audit.Commit(audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, Outcome: "refreshed", ReasonCode: "REFRESH", PolicyStatus: "not_evaluated"}); err != nil {
			o.store.Terminate(sess.ID)
			oauthError(w, 503, "temporarily_unavailable", "evidence journal unavailable")
			return
		}
		writeJSON(w, 200, o.tokenResponse(sess, tok))
	default:
		oauthError(w, 400, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

// revokeReused ends the session a reused authorization code created: a
// second redemption means the code leaked, so the tokens issued for it
// are no longer trusted.
func (o *OAuth) revokeReused(sessionID, clientID string) {
	ended := o.store.Terminate(sessionID)
	_ = o.audit.Commit(audit.Event{Class: "auth_failure", Origin: "E-03", SessionID: sessionID, Outcome: "deny", ReasonCode: "AUTH_CODE_REUSE",
		PolicyStatus: "not_evaluated", Detail: map[string]any{"client_id": clientID, "session_ended": ended}})
}

// recordCreated commits the session-creation event before any token leaves
// the Gateway; when evidence cannot be written the session is ended and the
// request fails closed.
func (o *OAuth) recordCreated(w http.ResponseWriter, sess *Session, reason, clientID string) bool {
	err := o.audit.Commit(audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, PolicyRevision: sess.PolicyRevision,
		Outcome: "created", ReasonCode: reason, PolicyStatus: "evaluated", Detail: map[string]string{"template": sess.Template, "approved_by": sess.ApprovedBy, "client_id": clientID,
			"observation_policy": sess.ObservationPolicy, "context_key": sess.ContextKey,
			"harness_type": sess.HarnessType, "harness_version": sess.HarnessVersion, "purpose": sess.Purpose, "project_root": sess.Project, "end_user": sess.EndUser}})
	if err != nil {
		o.store.Terminate(sess.ID)
		oauthError(w, 503, "temporarily_unavailable", "evidence journal unavailable")
		return false
	}
	return true
}

// Gateway errors of a refused session create request (FR-2.6, FR-2.10).
// The OAuth endpoints answer in the RFC 6749 error format; the Gateway error
// rides along as the smcp_error extension member with the Appendix B code,
// reason code and message.
const (
	ReasonTemplateNotPermitted = "TEMPLATE_NOT_PERMITTED"
	ReasonSessionLimit         = "SESSION_LIMIT"
)

var sessionErrorMessages = map[string]string{
	ReasonTemplateNotPermitted: "The requested policy template is not permitted for this agent. Request a template its framework profile allows, or none for the default.",
	ReasonSessionLimit:         "This agent already has the maximum number of open sessions. End one, then try again.",
}

func gatewayOAuthError(w http.ResponseWriter, status int, code, desc string, gwCode int, reason string) {
	writeJSON(w, status, map[string]any{"error": code, "error_description": desc,
		"smcp_error": map[string]any{"code": gwCode, "reasonCode": reason, "message": sessionErrorMessages[reason]}})
}

func (o *OAuth) sessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNoTemplate):
		gatewayOAuthError(w, 400, "invalid_scope", err.Error(), -31001, ReasonTemplateNotPermitted)
	case errors.Is(err, ErrTooManySessions):
		gatewayOAuthError(w, 429, "temporarily_unavailable", err.Error(), -31005, ReasonSessionLimit)
	case errors.Is(err, ErrNoSnapshot):
		oauthError(w, 503, "temporarily_unavailable", err.Error())
	default:
		oauthError(w, 400, "invalid_grant", err.Error())
	}
}

// tokenResponse is the RFC 6749 body plus the FR-2.4 session fields.
func (o *OAuth) tokenResponse(sess *Session, tok Tokens) map[string]any {
	claims := Claims{Template: sess.Template, Purpose: sess.Purpose, Project: sess.Project, EndUser: sess.EndUser}
	resp := map[string]any{
		"access_token":          tok.Access,
		"token_type":            "Bearer",
		"expires_in":            o.store.ExpiresIn(),
		"scope":                 claims.Scopes(),
		"session_id":            sess.ID,
		"expires_at":            sess.MaxDeadline.UTC().Format(time.RFC3339),
		"template_id":           sess.Template,
		"policy_revision_id":    sess.PolicyRevision,
		"observation_policy_id": nil,
	}
	if sess.ObservationPolicy != "" {
		resp["observation_policy_id"] = sess.ObservationPolicy // FR-2.4
	}
	if tok.Refresh != "" {
		resp["refresh_token"] = tok.Refresh
	}
	return resp
}

// FR-2.2 session API for header-helper adapters. Creation requires a
// confidential client (a secret), because there is no human sign-in step.
func (o *OAuth) sessionCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID       string `json:"client_id"`
		ClientSecret   string `json:"client_secret"`
		HarnessVersion string `json:"harness_version"`
		HarnessType    string `json:"harness_type"`
		Purpose        string `json:"purpose"`
		ProjectRoot    string `json:"project_root"`
		EndUser        string `json:"end_user"`
		TemplateID     string `json:"template_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		oauthError(w, 400, "invalid_request", "bad JSON")
		return
	}
	if u, p, ok := r.BasicAuth(); ok {
		body.ClientID, body.ClientSecret = u, p
	}
	src := authguard.Source(r)
	if d, err := o.guard.Check(src, "client:"+body.ClientID); err != nil {
		guardError(w, d, err)
		return
	}
	c := o.cfg.FindClient(body.ClientID)
	hash := ""
	if c != nil {
		hash = c.ClientSecretHash
	}
	ok, err := o.guard.Verify(r.Context(), hash, body.ClientSecret)
	if err != nil {
		guardError(w, time.Second, err)
		return
	}
	if !ok {
		o.guard.Failure(src, "client:"+body.ClientID)
		_ = o.audit.Commit(audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "deny", ReasonCode: "CLIENT_AUTH_FAILED", PolicyStatus: "not_evaluated", Detail: map[string]string{"client_id": body.ClientID}})
		oauthError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	o.guard.Success("client:" + body.ClientID)
	sess, tok, err := o.store.Create(CreateParams{PrincipalID: c.Principal, ClientID: c.ClientID, HarnessVersion: body.HarnessVersion, HarnessType: body.HarnessType,
		Claims: Claims{Template: body.TemplateID, Purpose: body.Purpose, Project: body.ProjectRoot, EndUser: body.EndUser}, Listener: listenerTLS})
	if err != nil {
		o.sessionError(w, err)
		return
	}
	if !o.recordCreated(w, sess, "SESSION_API", c.ClientID) {
		return
	}
	writeJSON(w, 201, o.tokenResponse(sess, tok))
}

// Bearer extracts the bearer token of a request (header only, FR-2.5).
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (o *OAuth) ownSession(w http.ResponseWriter, r *http.Request) *Session {
	sess, err := o.store.Authenticate(Bearer(r), listenerTLS)
	if err != nil || sess.ID != r.PathValue("id") {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, o.ResourceMetadataURL()))
		oauthError(w, 401, "invalid_token", "session invalid")
		return nil
	}
	return sess
}

func (o *OAuth) sessionGet(w http.ResponseWriter, r *http.Request) {
	sess := o.ownSession(w, r)
	if sess == nil {
		return
	}
	writeJSON(w, 200, map[string]any{"session_id": sess.ID, "state": sess.State, "template_id": sess.Template,
		"policy_revision_id": sess.PolicyRevision, "expires_at": sess.MaxDeadline.UTC().Format(time.RFC3339), "idle_deadline": sess.IdleDeadline.UTC().Format(time.RFC3339)})
}

func (o *OAuth) sessionDelete(w http.ResponseWriter, r *http.Request) {
	sess := o.ownSession(w, r)
	if sess == nil {
		return
	}
	o.store.Terminate(sess.ID)
	_ = o.audit.Commit(audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, Outcome: StateTerminated, ReasonCode: "SESSION_API", PolicyStatus: "not_evaluated"})
	w.WriteHeader(http.StatusNoContent)
}
