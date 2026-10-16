package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// OAuth is the local OAuth 2.1 authorization server of FR-2.17 to FR-2.22
// and the session API of FR-2.2, mounted on the harness listener.
type OAuth struct {
	cfg   *config.Config
	store *Store
	audit func(audit.Event)
	now   func() time.Time

	mu    sync.Mutex
	codes map[string]*authCode // keyed by SHA-256 of the code
}

type authCode struct {
	clientID    string
	principalID string
	redirectURI string
	challenge   string
	claims      Claims
	scope       string
	resource    string
	adminUser   string
	expires     time.Time
}

const (
	pathPRM       = "/.well-known/oauth-protected-resource"
	pathASM       = "/.well-known/oauth-authorization-server"
	pathAuthorize = "/oauth/authorize"
	pathToken     = "/oauth/token"
	pathSessions  = "/smcp/v1/sessions"
	codeLifetime  = 10 * time.Minute
	listenerTLS   = "tls"
)

// NewOAuth builds the authorization server over the session store.
func NewOAuth(cfg *config.Config, store *Store, auditFn func(audit.Event)) *OAuth {
	if auditFn == nil {
		auditFn = func(audit.Event) {}
	}
	return &OAuth{cfg: cfg, store: store, audit: auditFn, now: time.Now, codes: map[string]*authCode{}}
}

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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// FR-2.17: protected-resource metadata (RFC 9728).
func (o *OAuth) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource":                 o.cfg.ResourceURI(),
		"authorization_servers":    []string{o.cfg.Listener.PublicURL},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Secure MCP Gateway",
	})
}

// FR-2.17: authorization-server metadata (RFC 8414).
func (o *OAuth) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	base := o.cfg.Listener.PublicURL
	var scopes []string
	if snap := o.store.snapshot(); snap != nil {
		for name := range snap.Profiles {
			for _, t := range snap.Profiles[name].Templates {
				s := "smcp:template:" + t
				if !contains(scopes, s) {
					scopes = append(scopes, s)
				}
			}
		}
	}
	writeJSON(w, 200, map[string]any{
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
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	})
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// redirectAllowed matches a redirect URI against the client's registered
// URIs. A registered loopback URI with port "*" matches any port, as the
// Client ID Metadata Document profile permits for native clients.
func redirectAllowed(c *config.Client, uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.Fragment != "" {
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
			u.Scheme == ru.Scheme && u.Hostname() == ru.Hostname() && u.Path == ru.Path {
			return true
		}
	}
	return false
}

type authorizeParams struct {
	ClientID, RedirectURI, State, Scope, Challenge, Method, Resource, ResponseType string
}

func (o *OAuth) parseAuthorize(v url.Values) (authorizeParams, *config.Client, string) {
	p := authorizeParams{
		ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), State: v.Get("state"), Scope: v.Get("scope"),
		Challenge: v.Get("code_challenge"), Method: v.Get("code_challenge_method"), Resource: v.Get("resource"), ResponseType: v.Get("response_type"),
	}
	c := o.cfg.FindClient(p.ClientID)
	if c == nil {
		return p, nil, "unknown client_id"
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
<p>A framework instance is asking for a Gateway session. Sign in as an administrator to approve it.</p>
<dl><dt>Client</dt><dd>{{.ClientID}}</dd><dt>Principal</dt><dd>{{.Principal}}</dd><dt>Requested scope</dt><dd>{{if .Scope}}{{.Scope}}{{else}}(default template){{end}}</dd></dl>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Approve and continue</button></form></body></html>`))

func (o *OAuth) renderLogin(w http.ResponseWriter, p authorizeParams, c *config.Client, errMsg string) {
	hidden := map[string]string{
		"client_id": p.ClientID, "redirect_uri": p.RedirectURI, "state": p.State, "scope": p.Scope,
		"code_challenge": p.Challenge, "code_challenge_method": p.Method, "resource": p.Resource, "response_type": p.ResponseType,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	if errMsg != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	_ = loginPage.Execute(w, map[string]any{
		"ClientID": p.ClientID, "Principal": c.Principal, "Scope": p.Scope, "Error": errMsg, "Action": pathAuthorize, "Hidden": hidden,
	})
}

// FR-2.19: authorization endpoint, step 1 (validate and show sign-in).
func (o *OAuth) authorizeGET(w http.ResponseWriter, r *http.Request) {
	p, c, bad := o.parseAuthorize(r.URL.Query())
	if bad != "" {
		http.Error(w, bad, http.StatusBadRequest)
		return
	}
	if msg := o.checkAuthorize(p); msg != "" {
		o.redirectError(w, r, p, "invalid_request", msg)
		return
	}
	o.renderLogin(w, p, c, "")
}

func (o *OAuth) checkAuthorize(p authorizeParams) string {
	if p.ResponseType != "code" {
		return "response_type must be code"
	}
	if p.Method != "S256" || len(p.Challenge) < 43 {
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

// FR-2.19: authorization endpoint, step 2 (administrator sign-in, code issue).
func (o *OAuth) authorizePOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	p, c, bad := o.parseAuthorize(r.PostForm)
	if bad != "" {
		http.Error(w, bad, http.StatusBadRequest)
		return
	}
	if msg := o.checkAuthorize(p); msg != "" {
		o.redirectError(w, r, p, "invalid_request", msg)
		return
	}
	user, pw := r.PostForm.Get("username"), r.PostForm.Get("password")
	if user != o.cfg.Admin.Username || !keys.VerifyPassword(o.cfg.Admin.PasswordHash, pw) {
		o.audit(audit.Event{Class: "auth_failure", Origin: "E-24", Outcome: "deny", ReasonCode: "ADMIN_SIGNIN_FAILED", PolicyStatus: "not_evaluated", Detail: map[string]string{"client_id": p.ClientID}})
		o.renderLogin(w, p, c, "Sign-in failed.")
		return
	}
	claims, _ := ParseScopes(strings.Fields(p.Scope))
	code := ids.Secret()
	o.mu.Lock()
	o.codes[hash(code)] = &authCode{clientID: c.ClientID, principalID: c.Principal, redirectURI: p.RedirectURI, challenge: p.Challenge,
		claims: claims, scope: p.Scope, resource: p.Resource, adminUser: user, expires: o.now().Add(codeLifetime)}
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
func (o *OAuth) clientAuth(r *http.Request) (*config.Client, string) {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		id, secret = u, p
	}
	c := o.cfg.FindClient(id)
	if c == nil {
		return nil, "unknown client"
	}
	if c.ClientSecretHash != "" && !keys.VerifyPassword(c.ClientSecretHash, secret) {
		return nil, "client authentication failed"
	}
	return c, ""
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
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "bad form")
		return
	}
	c, bad := o.clientAuth(r)
	if bad != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="smcp"`)
		oauthError(w, 401, "invalid_client", bad)
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		o.mu.Lock()
		key := hash(r.PostForm.Get("code"))
		ac := o.codes[key]
		delete(o.codes, key) // one use
		o.mu.Unlock()
		if ac == nil || o.now().After(ac.expires) || ac.clientID != c.ClientID {
			oauthError(w, 400, "invalid_grant", "code unknown, expired or issued to another client")
			return
		}
		if ac.redirectURI != r.PostForm.Get("redirect_uri") {
			oauthError(w, 400, "invalid_grant", "redirect_uri mismatch")
			return
		}
		if !pkceOK(r.PostForm.Get("code_verifier"), ac.challenge) {
			oauthError(w, 400, "invalid_grant", "PKCE verification failed")
			return
		}
		if res := r.PostForm.Get("resource"); res != "" && res != ac.resource {
			oauthError(w, 400, "invalid_target", "resource mismatch")
			return
		}
		sess, tok, err := o.store.Create(CreateParams{PrincipalID: ac.principalID, ClientID: c.ClientID, Claims: ac.claims, ApprovedBy: ac.adminUser, Listener: listenerTLS})
		if err != nil {
			o.sessionError(w, err)
			return
		}
		o.audit(audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, PolicyRevision: sess.PolicyRevision, Outcome: "created", ReasonCode: "OAUTH_CODE", PolicyStatus: "evaluated", Detail: map[string]string{"template": sess.Template, "approved_by": sess.ApprovedBy, "client_id": c.ClientID}})
		writeJSON(w, 200, o.tokenResponse(sess, tok))
	case "refresh_token":
		sess, tok, err := o.store.Refresh(r.PostForm.Get("refresh_token"))
		if err != nil {
			oauthError(w, 400, "invalid_grant", "refresh token invalid or session ended")
			return
		}
		if sess.ClientID != c.ClientID {
			oauthError(w, 400, "invalid_grant", "refresh token issued to another client")
			return
		}
		writeJSON(w, 200, o.tokenResponse(sess, tok))
	default:
		oauthError(w, 400, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (o *OAuth) sessionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNoTemplate):
		oauthError(w, 400, "invalid_scope", err.Error())
	case errors.Is(err, ErrTooManySessions):
		oauthError(w, 429, "temporarily_unavailable", err.Error())
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
	c := o.cfg.FindClient(body.ClientID)
	if c == nil || c.ClientSecretHash == "" || !keys.VerifyPassword(c.ClientSecretHash, body.ClientSecret) {
		o.audit(audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "deny", ReasonCode: "CLIENT_AUTH_FAILED", PolicyStatus: "not_evaluated", Detail: map[string]string{"client_id": body.ClientID}})
		oauthError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	sess, tok, err := o.store.Create(CreateParams{PrincipalID: c.Principal, ClientID: c.ClientID, HarnessVersion: body.HarnessVersion,
		Claims: Claims{Template: body.TemplateID, Purpose: body.Purpose, Project: body.ProjectRoot, EndUser: body.EndUser}, Listener: listenerTLS})
	if err != nil {
		o.sessionError(w, err)
		return
	}
	o.audit(audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, PolicyRevision: sess.PolicyRevision, Outcome: "created", ReasonCode: "SESSION_API", PolicyStatus: "evaluated", Detail: map[string]string{"template": sess.Template, "client_id": c.ClientID}})
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
	o.audit(audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, Outcome: "terminated", ReasonCode: "SESSION_API", PolicyStatus: "not_evaluated"})
	w.WriteHeader(http.StatusNoContent)
}
