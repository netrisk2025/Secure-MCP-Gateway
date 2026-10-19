package remote

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/authguard"
	"github.com/ethan03805/secure-mcp-gateway/internal/channel"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

// Grant types.
const (
	grantCode    = "authorization_code"
	grantRefresh = "refresh_token"
	grantDevice  = "urn:ietf:params:oauth:grant-type:device_code"
)

const (
	codeLifetime   = 10 * time.Minute
	deviceLifetime = 10 * time.Minute
	deviceInterval = 5 * time.Second
	maxCodes       = 256
	maxDevices     = 64
	// MessagePending is the OAuth error description for a client whose
	// dynamic registration has not been approved (FR-16.5).
	MessagePending = "client registration is pending operator approval; ask the Gateway operator to run: smcpctl clients approve <client_id>"
)

type authCode struct {
	clientID, principal, redirectURI, challenge, approver string
	claims                                                session.Claims
	expires                                               time.Time
}

type deviceGrant struct {
	clientID, principal, userCode, scope string
	claims                               session.Claims
	expires, lastPoll                    time.Time
	status, approver                     string // pending, approved, denied
}

type oauthState struct {
	mu      sync.Mutex
	codes   map[string]*authCode    // by SHA-256 of the code
	devices map[string]*deviceGrant // by SHA-256 of the device code
	users   map[string]string       // user code -> device key
	// redeemed maps the SHA-256 of a redeemed code to the session it
	// created, until the code would have expired, so that a second
	// redemption revokes that session (OAuth 2.1 section 4.1.3).
	redeemed map[string]redeemedCode
}

type redeemedCode struct {
	sessionID string
	expires   time.Time
}

func newOAuthState() *oauthState {
	return &oauthState{codes: map[string]*authCode{}, devices: map[string]*deviceGrant{}, users: map[string]string{}, redeemed: map[string]redeemedCode{}}
}

func (o *oauthState) prune(now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, c := range o.codes {
		if now.After(c.expires) {
			delete(o.codes, k)
		}
	}
	for k, d := range o.devices {
		if now.After(d.expires) {
			delete(o.devices, k)
			delete(o.users, d.userCode)
		}
	}
	for k, c := range o.redeemed {
		if now.After(c.expires) {
			delete(o.redeemed, k)
		}
	}
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// rclient is a client allowed on the remote listener: a pre-registered
// [[client]] listed in remote.clients, or a dynamic registration.
type rclient struct {
	id, secretHash, principal, status string
	redirects, grants                 []string
	dynamic                           bool
}

func (c rclient) allowsGrant(g string) bool {
	if !c.dynamic {
		return true
	}
	if g == grantRefresh {
		return true
	}
	return slices.Contains(c.grants, g)
}

func (s *Service) findClient(id string) (rclient, bool) {
	if id == "" {
		return rclient{}, false
	}
	if slices.Contains(s.cfg.Remote.Clients, id) {
		if c := s.cfg.FindClient(id); c != nil {
			return rclient{id: c.ClientID, secretHash: c.ClientSecretHash, principal: c.Principal, status: StatusApproved, redirects: c.RedirectURIs}, true
		}
	}
	if g, ok := s.reg.get(id); ok {
		return rclient{id: g.ClientID, secretHash: g.SecretHash, principal: g.Principal, status: g.Status, redirects: g.RedirectURIs, grants: g.GrantTypes, dynamic: true}, true
	}
	return rclient{}, false
}

// commit writes an event with the request's remote origin.
func (s *Service) commit(ctx context.Context, e audit.Event) error {
	channel.From(ctx).Apply(&e)
	if e.PolicyStatus == "" {
		e.PolicyStatus = "not_evaluated"
	}
	err := s.rec.Commit(e)
	if err != nil {
		s.log.Error("evidence write failed", "err", err)
	}
	return err
}

// fail records a failed sign-in or token request for the client ID and the
// source address; the CP-49 consecutive-failure count then locks both
// (FR-16.6), and the lockout is itself recorded.
func (s *Service) fail(r *http.Request, clientID, reason string) {
	src := sourceKey(r)
	account := "client:" + clientID
	s.guard.Failure(src, account)
	_ = s.commit(r.Context(), audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "deny", ReasonCode: reason, ClientID: clientID})
	if _, err := s.guard.Check(src, account); errors.Is(err, authguard.ErrLocked) {
		_ = s.commit(r.Context(), audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "locked", ReasonCode: "REMOTE_LOCKOUT", ClientID: clientID,
			Detail: map[string]any{"lockout": s.cfg.Remote.Limits.Lockout.String(), "failures": s.cfg.Remote.Limits.LockoutFailures}})
	}
}

// locked reports a client ID or source under lockout.
func (s *Service) locked(w http.ResponseWriter, r *http.Request, clientID string) bool {
	d, err := s.guard.Check(sourceKey(r), "client:"+clientID)
	if err == nil {
		return false
	}
	authguard.RetryAfter(w, d)
	oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many failed attempts; locked for "+s.cfg.Remote.Limits.Lockout.String())
	return true
}

// approverAccount is the lockout key of a Session Approver username on the
// remote listener.
func approverAccount(user string) string { return "approver:" + user }

// approverLocked reports a sign-in refused because the client, the source
// or the Session Approver username is locked. The username locks after
// twice the client threshold, counted over every client and source, so
// password guesses cannot be spread over several approved clients and
// source addresses.
func (s *Service) approverLocked(r *http.Request, clientID, user string) bool {
	if _, err := s.guard.Check(sourceKey(r), "client:"+clientID); err != nil {
		return true
	}
	_, err := s.approvers.Check(sourceKey(r), approverAccount(user))
	return err != nil
}

// approverFailed records a failed Session Approver sign-in against the
// client, the source and the username.
func (s *Service) approverFailed(r *http.Request, clientID, user string) {
	s.approvers.FailAccount(approverAccount(user))
	s.fail(r, clientID, "APPROVER_SIGNIN_FAILED")
	if _, err := s.approvers.Check(sourceKey(r), approverAccount(user)); errors.Is(err, authguard.ErrLocked) {
		// The username is recorded only as a digest prefix: a failed
		// sign-in may carry a password typed into the username field.
		_ = s.commit(r.Context(), audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "locked", ReasonCode: "REMOTE_APPROVER_LOCKOUT", ClientID: clientID,
			Detail: map[string]any{"username_sha256": sum(user)[:16], "lockout": s.cfg.Remote.Limits.Lockout.String(), "failures": 2 * s.cfg.Remote.Limits.LockoutFailures}})
	}
}

// FR-16.3: protected-resource metadata naming the public URL.
func (s *Service) protectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resourceURI(),
		"authorization_servers":    []string{s.publicURL()},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Secure MCP Gateway (remote access)",
	})
}

func (s *Service) authorizationServerMetadata(w http.ResponseWriter, _ *http.Request) {
	base := s.publicURL()
	var scopes []string
	for _, t := range s.cfg.Remote.Templates {
		scopes = append(scopes, "smcp:template:"+t)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         base,
		"authorization_endpoint":                         base + pathAuthorize,
		"token_endpoint":                                 base + pathToken,
		"registration_endpoint":                          base + pathRegister,
		"device_authorization_endpoint":                  base + pathDeviceAuth,
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{grantCode, grantRefresh, grantDevice},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
		"scopes_supported":                               scopes,
		"authorization_response_iss_parameter_supported": true,
		"smcp_registration_requires_approval":            true,
	})
}

func boundText(s string, n int) string {
	s = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// registrationRefused answers a registration refused for a full pending
// queue or a caller address over its pending quota.
func registrationRefused(w http.ResponseWriter, err error) {
	msg := "too many registrations are waiting for approval"
	if errors.Is(err, errSourceQuota) {
		msg = "too many registrations from this address are waiting for approval"
	}
	oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", msg)
}

// FR-16.5: RFC 7591 registration, stored as pending.
func (s *Service) register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
		SoftwareID              string   `json:"software_id"`
		SoftwareVersion         string   `json:"software_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "body must be a JSON client metadata object")
		return
	}
	if len(body.GrantTypes) == 0 {
		body.GrantTypes = []string{grantCode}
	}
	for _, g := range body.GrantTypes {
		if g != grantCode && g != grantRefresh && g != grantDevice {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant type "+boundText(g, 80))
			return
		}
	}
	for _, rt := range body.ResponseTypes {
		if rt != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "response_types must be [\"code\"]")
			return
		}
	}
	if slices.Contains(body.GrantTypes, grantCode) && len(body.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required for the authorization_code grant")
		return
	}
	if len(body.RedirectURIs) > 8 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "at most 8 redirect_uris")
		return
	}
	for _, u := range body.RedirectURIs {
		if !validRedirect(u) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URIs must be https, or http on a loopback address")
			return
		}
	}
	method := body.TokenEndpointAuthMethod
	if method == "" {
		method = "client_secret_basic" // RFC 7591 section 2 default
	}
	if method != "none" && method != "client_secret_basic" && method != "client_secret_post" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method must be none, client_secret_basic or client_secret_post")
		return
	}
	// Refuse before any costly work or evidence when no pending slot is
	// free, in total or for this caller address (RR-02); reg.add checks
	// again under its lock.
	source := channel.From(r.Context()).ClientAddress
	if err := s.reg.full(source); err != nil {
		registrationRefused(w, err)
		return
	}
	now := s.now()
	g := &Registration{ClientID: "smcp-dcr-" + ids.New(), ClientName: boundText(body.ClientName, 128), RedirectURIs: body.RedirectURIs,
		GrantTypes: body.GrantTypes, TokenEndpointAuthMethod: method, SoftwareID: boundText(body.SoftwareID, 128),
		SoftwareVersion: boundText(body.SoftwareVersion, 64), Status: StatusPending, RegisteredAt: now.UTC(),
		SourceAddress: source}
	secret := ""
	if method != "none" {
		secret = ids.Secret()
		// Argon2id takes 64 MiB per evaluation; the guard bounds how many
		// run at once, as for sign-in, so unauthenticated registrations
		// cannot exhaust memory.
		h, err := s.guard.Hash(r.Context(), secret)
		if errors.Is(err, authguard.ErrBusy) {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration capacity exhausted; retry shortly")
			return
		}
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "could not protect the client secret")
			return
		}
		g.SecretHash = h
	}
	if err := s.commit(r.Context(), audit.Event{Class: "client_registration", Origin: "E-03", Outcome: StatusPending, ReasonCode: "DCR_PENDING", ClientID: g.ClientID,
		Detail: map[string]any{"client_name": g.ClientName, "redirect_uris": g.RedirectURIs, "grant_types": g.GrantTypes, "software_id": g.SoftwareID}}); err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "evidence journal unavailable")
		return
	}
	if err := s.reg.add(g); err != nil {
		if errors.Is(err, errTooMany) || errors.Is(err, errSourceQuota) {
			registrationRefused(w, err)
			return
		}
		oauthError(w, http.StatusInternalServerError, "server_error", "registration could not be stored")
		return
	}
	resp := map[string]any{"client_id": g.ClientID, "client_id_issued_at": now.Unix(), "redirect_uris": g.RedirectURIs, "grant_types": g.GrantTypes,
		"token_endpoint_auth_method": method, "client_name": g.ClientName, "response_types": []string{"code"},
		"smcp_registration_status": StatusPending, "smcp_message": "registration stored; it can be used after the Gateway operator approves it"}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	s.log.Info("remote client registration pending", "client_id", g.ClientID, "client_name", g.ClientName)
	writeJSON(w, http.StatusCreated, resp)
}

// clientAuth authenticates the client of a token or device request.
// Pending registrations get the FR-16.5 message.
func (s *Service) clientAuth(w http.ResponseWriter, r *http.Request) (rclient, bool) {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		id, secret = u, p
	}
	if s.locked(w, r, id) {
		return rclient{}, false
	}
	c, ok := s.findClient(id)
	if !ok {
		if secret != "" {
			_, _ = s.guard.Verify(r.Context(), "", secret)
		}
		s.fail(r, id, "CLIENT_AUTH_FAILED")
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return rclient{}, false
	}
	switch c.status {
	case StatusPending:
		_ = s.commit(r.Context(), audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "deny", ReasonCode: "DCR_PENDING", ClientID: id})
		oauthError(w, http.StatusUnauthorized, "invalid_client", MessagePending)
		return rclient{}, false
	case StatusApproved:
	default:
		s.fail(r, id, "CLIENT_NOT_APPROVED")
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client registration was "+c.status)
		return rclient{}, false
	}
	if c.secretHash != "" {
		ok, err := s.guard.Verify(r.Context(), c.secretHash, secret)
		if err != nil {
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "authentication capacity exhausted")
			return rclient{}, false
		}
		if !ok {
			s.fail(r, id, "CLIENT_AUTH_FAILED")
			oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return rclient{}, false
		}
	}
	return c, true
}

type authorizeParams struct {
	ClientID, RedirectURI, State, Scope, Challenge, Method, Resource, ResponseType string
}

func paramsFrom(v url.Values) authorizeParams {
	return authorizeParams{ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), State: v.Get("state"), Scope: v.Get("scope"),
		Challenge: v.Get("code_challenge"), Method: v.Get("code_challenge_method"), Resource: v.Get("resource"), ResponseType: v.Get("response_type")}
}

func (s *Service) redirectWith(w http.ResponseWriter, r *http.Request, p authorizeParams, q url.Values) {
	u, _ := url.Parse(p.RedirectURI)
	vals := u.Query()
	for k, v := range q {
		vals[k] = v
	}
	vals.Set("iss", s.publicURL())
	if p.State != "" {
		vals.Set("state", p.State)
	}
	u.RawQuery = vals.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Service) redirectError(w http.ResponseWriter, r *http.Request, p authorizeParams, code, desc string) {
	s.redirectWith(w, r, p, url.Values{"error": {code}, "error_description": {desc}})
}

// checkAuthorize validates an authorization request; it returns the client
// and, when the redirect URI cannot be trusted, a plain error text.
func (s *Service) checkAuthorize(w http.ResponseWriter, r *http.Request, p authorizeParams) (rclient, bool) {
	c, ok := s.findClient(p.ClientID)
	if !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return c, false
	}
	if !redirectMatches(c.redirects, p.RedirectURI) {
		http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
		return c, false
	}
	if c.status == StatusPending { // FR-16.5
		_ = s.commit(r.Context(), audit.Event{Class: "auth_failure", Origin: "E-03", Outcome: "deny", ReasonCode: "DCR_PENDING", ClientID: c.id})
		s.redirectError(w, r, p, "unauthorized_client", MessagePending)
		return c, false
	}
	if c.status != StatusApproved {
		s.redirectError(w, r, p, "unauthorized_client", "client registration was "+c.status)
		return c, false
	}
	if !c.allowsGrant(grantCode) {
		s.redirectError(w, r, p, "unauthorized_client", "client is not registered for the authorization_code grant")
		return c, false
	}
	msg := ""
	switch {
	case p.ResponseType != "code":
		msg = "response_type must be code"
	case p.Method != "S256" || len(p.Challenge) != 43:
		msg = "PKCE S256 code_challenge is required"
	case p.Resource != "" && p.Resource != s.resourceURI():
		msg = "resource must be " + s.resourceURI()
	}
	if msg == "" {
		if _, err := session.ParseScopes(strings.Fields(p.Scope)); err != nil {
			msg = err.Error()
		}
	}
	if msg != "" {
		s.redirectError(w, r, p, "invalid_request", msg)
		return c, false
	}
	return c, true
}

var signinPage = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure MCP Gateway remote sign-in</title>
<style>body{font:16px system-ui,sans-serif;padding:24px;max-width:30rem;margin:auto;color:#111;background:#fafafa}
h1{font-size:1.25rem}label{display:block;margin:12px 0 4px}input{width:100%;box-sizing:border-box;padding:8px;font-size:16px}
button{margin:16px 8px 0 0;padding:10px 16px;font-size:16px}dl{font-size:14px;background:#fff;padding:12px;border:1px solid #ddd}dt{font-weight:600}dd{margin:0 0 8px;word-break:break-all}.err{color:#a00}.warn{background:#fff4e5;padding:8px;border:1px solid #f0c36d}</style></head>
<body><h1>Secure MCP Gateway: remote access</h1>
<p class="warn">This request arrived through the Remote Access tunnel from an agent running on another computer.</p>
<p>{{.Lead}}</p>
<dl><dt>Client</dt><dd>{{.ClientID}}</dd>{{if .ClientName}}<dt>Client name (self-declared)</dt><dd>{{.ClientName}}</dd>{{end}}<dt>Principal</dt><dd>{{.Principal}}</dd><dt>Requested template</dt><dd>{{.Template}}</dd><dt>Requested scope</dt><dd>{{if .Scope}}{{.Scope}}{{else}}(default template){{end}}</dd><dt>Caller address (reported by the tunnel)</dt><dd>{{.Address}}</dd></dl>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
{{if .AskCode}}<label for="c">Code shown by the agent</label><input id="c" name="user_code" value="{{.UserCode}}" autocomplete="off" required>{{end}}
<label for="u">Session Approver username</label><input id="u" name="username" autocomplete="username" required>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit" name="decision" value="approve">Approve</button>{{if .AskCode}}<button type="submit" name="decision" value="deny" formnovalidate>Deny</button>{{end}}</form></body></html>`))

func (s *Service) renderSignin(w http.ResponseWriter, r *http.Request, status int, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	session.SecurityHeaders(w.Header())
	w.WriteHeader(status)
	data["Address"] = channel.From(r.Context()).ClientAddress
	_ = signinPage.Execute(w, data)
}

func (s *Service) authorizeData(p authorizeParams, c rclient, errMsg string) map[string]any {
	name := ""
	if g, ok := s.reg.get(c.id); ok {
		name = g.ClientName
	}
	return map[string]any{"Lead": "Sign in as a Session Approver to give this agent a Gateway session.", "ClientID": c.id, "ClientName": name,
		"Principal": c.principal, "Template": session.TemplateLabel(p.Scope), "Scope": p.Scope, "Error": errMsg, "Action": pathAuthorize,
		"Hidden": map[string]string{"client_id": p.ClientID, "redirect_uri": p.RedirectURI, "state": p.State, "scope": p.Scope,
			"code_challenge": p.Challenge, "code_challenge_method": p.Method, "resource": p.Resource, "response_type": p.ResponseType}}
}

func (s *Service) authorizeGET(w http.ResponseWriter, r *http.Request) {
	session.SecurityHeaders(w.Header())
	p := paramsFrom(r.URL.Query())
	c, ok := s.checkAuthorize(w, r, p)
	if !ok {
		return
	}
	s.renderSignin(w, r, http.StatusOK, s.authorizeData(p, c, ""))
}

// verifyApprover checks a Session Approver sign-in in constant time with
// respect to whether the username exists.
func (s *Service) verifyApprover(ctx context.Context, user, pw string) (bool, error) {
	hash := ""
	for _, a := range s.cfg.SessionApprovers() {
		if authguard.EqualName(a.Username, user) {
			hash = a.PasswordHash
		}
	}
	return s.guard.Verify(ctx, hash, pw)
}

func (s *Service) authorizePOST(w http.ResponseWriter, r *http.Request) {
	session.SecurityHeaders(w.Header())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	p := paramsFrom(r.PostForm)
	c, ok := s.checkAuthorize(w, r, p)
	if !ok {
		return
	}
	user := r.PostForm.Get("username")
	if s.approverLocked(r, c.id, user) {
		s.renderSignin(w, r, http.StatusTooManyRequests, s.authorizeData(p, c, "Too many failed attempts. Sign-in is locked for "+s.cfg.Remote.Limits.Lockout.String()+"."))
		return
	}
	ok, err := s.verifyApprover(r.Context(), user, r.PostForm.Get("password"))
	if err != nil {
		s.renderSignin(w, r, http.StatusServiceUnavailable, s.authorizeData(p, c, "Sign-in is busy. Try again in a moment."))
		return
	}
	if !ok {
		s.approverFailed(r, c.id, user)
		s.renderSignin(w, r, http.StatusUnauthorized, s.authorizeData(p, c, "Sign-in failed."))
		return
	}
	s.guard.Success("client:" + c.id)
	s.approvers.Success(approverAccount(user))
	claims, _ := session.ParseScopes(strings.Fields(p.Scope))
	code := ids.Secret()
	s.oauth.mu.Lock()
	if len(s.oauth.codes) >= maxCodes {
		s.oauth.mu.Unlock()
		s.redirectError(w, r, p, "temporarily_unavailable", "too many outstanding authorization codes")
		return
	}
	s.oauth.codes[sum(code)] = &authCode{clientID: c.id, principal: c.principal, redirectURI: p.RedirectURI, challenge: p.Challenge, approver: user,
		claims: claims, expires: s.now().Add(codeLifetime)}
	s.oauth.mu.Unlock()
	s.redirectWith(w, r, p, url.Values{"code": {code}})
}

func pkceOK(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(h[:])), []byte(challenge)) == 1
}

// token serves the authorization-code, refresh and device-code grants.
func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	c, ok := s.clientAuth(w, r)
	if !ok {
		return
	}
	grant := r.PostForm.Get("grant_type")
	if !c.allowsGrant(grant) {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "client is not registered for this grant type")
		return
	}
	switch grant {
	case grantCode:
		s.oauth.mu.Lock()
		key := sum(r.PostForm.Get("code"))
		ac := s.oauth.codes[key]
		delete(s.oauth.codes, key) // one use
		reused, wasRedeemed := s.oauth.redeemed[key]
		s.oauth.mu.Unlock()
		if ac == nil && wasRedeemed && s.now().Before(reused.expires) {
			// A second redemption means the code leaked: the session it
			// created is no longer trusted.
			ended := s.store.Terminate(reused.sessionID)
			_ = s.commit(r.Context(), audit.Event{Class: "auth_failure", Origin: "E-03", SessionID: reused.sessionID, Outcome: "deny", ReasonCode: "AUTH_CODE_REUSE",
				ClientID: c.id, Detail: map[string]any{"session_ended": ended}})
			s.fail(r, c.id, "INVALID_GRANT")
			oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code already used; the session it created has been revoked")
			return
		}
		switch {
		case ac == nil || s.now().After(ac.expires) || ac.clientID != c.id:
			s.fail(r, c.id, "INVALID_GRANT")
			oauthError(w, http.StatusBadRequest, "invalid_grant", "code unknown, expired or issued to another client")
			return
		case ac.redirectURI != r.PostForm.Get("redirect_uri"):
			s.fail(r, c.id, "INVALID_GRANT")
			oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		case !pkceOK(r.PostForm.Get("code_verifier"), ac.challenge):
			s.fail(r, c.id, "INVALID_GRANT")
			oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
		if res := r.PostForm.Get("resource"); res != "" && res != s.resourceURI() {
			oauthError(w, http.StatusBadRequest, "invalid_target", "resource mismatch")
			return
		}
		if sess := s.issue(w, r, c, ac.principal, ac.claims, ac.approver, "OAUTH_CODE"); sess != nil {
			s.oauth.mu.Lock()
			if len(s.oauth.redeemed) < maxCodes {
				s.oauth.redeemed[key] = redeemedCode{sessionID: sess.ID, expires: ac.expires}
			}
			s.oauth.mu.Unlock()
		}
	case grantRefresh:
		sess, tok, err := s.store.Refresh(r.PostForm.Get("refresh_token"), c.id)
		if errors.Is(err, session.ErrRefreshReuse) {
			_ = s.commit(r.Context(), audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, Outcome: session.StateTerminated,
				ReasonCode: session.EndRefreshReuse, ClientID: c.id})
			oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected; the session has been revoked")
			return
		}
		if err != nil || sess.Listener != channel.Remote {
			if err == nil {
				s.store.Terminate(sess.ID)
			}
			s.fail(r, c.id, "INVALID_GRANT")
			oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token invalid, issued to another client or session ended")
			return
		}
		if err := s.commit(r.Context(), audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, Outcome: "refreshed", ReasonCode: "REFRESH", ClientID: c.id}); err != nil {
			s.store.Terminate(sess.ID)
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "evidence journal unavailable")
			return
		}
		writeJSON(w, http.StatusOK, s.tokenResponse(sess, tok))
	case grantDevice:
		s.devicePoll(w, r, c)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code, refresh_token or "+grantDevice)
	}
}

// issue creates a remote session (FR-16.12) and returns its tokens. The
// creation event is committed before any token leaves the Gateway. It
// returns the session, or nil when it answered with an error.
func (s *Service) issue(w http.ResponseWriter, r *http.Request, c rclient, principal string, claims session.Claims, approver, reason string) *session.Session {
	if principal == "" {
		oauthError(w, http.StatusBadRequest, "invalid_client", "client is not bound to a principal")
		return nil
	}
	l := s.cfg.Remote.Limits
	sess, tok, err := s.store.Create(session.CreateParams{PrincipalID: principal, ClientID: c.id, Claims: claims, ApprovedBy: approver,
		Listener: channel.Remote, MaxLifetime: l.SessionMaxLifetime.Duration, IdleTimeout: l.SessionIdleTimeout.Duration,
		AllowedTemplates: append([]string{}, s.cfg.Remote.Templates...), ClientAddress: channel.From(r.Context()).ClientAddress, Remote: true})
	if err != nil {
		switch {
		case errors.Is(err, session.ErrNoTemplate):
			_ = s.commit(r.Context(), audit.Event{Class: "session", Origin: "E-04", PrincipalID: principal, Outcome: "deny", ReasonCode: "REMOTE_TEMPLATE_REFUSED", ClientID: c.id,
				Detail: map[string]any{"template": claims.Template}})
			oauthError(w, http.StatusBadRequest, "invalid_scope", "template not allowed for remote sessions (remote.templates)")
		case errors.Is(err, session.ErrTooManySessions):
			oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", err.Error())
		case errors.Is(err, session.ErrNoSnapshot):
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", err.Error())
		default:
			oauthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		}
		return nil
	}
	if err := s.commit(r.Context(), audit.Event{Class: "session", Origin: "E-04", SessionID: sess.ID, PrincipalID: sess.PrincipalID, PolicyRevision: sess.PolicyRevision,
		Outcome: "created", ReasonCode: reason, PolicyStatus: "evaluated", ClientID: c.id,
		Detail: map[string]string{"template": sess.Template, "approved_by": sess.ApprovedBy,
			"observation_policy": sess.ObservationPolicy, "context_key": sess.ContextKey}}); err != nil {
		s.store.Terminate(sess.ID)
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "evidence journal unavailable")
		return nil
	}
	s.guard.Success("client:" + c.id)
	writeJSON(w, http.StatusOK, s.tokenResponse(sess, tok))
	return sess
}

func (s *Service) tokenResponse(sess *session.Session, tok session.Tokens) map[string]any {
	claims := session.Claims{Template: sess.Template, Purpose: sess.Purpose, Project: sess.Project, EndUser: sess.EndUser}
	resp := map[string]any{"access_token": tok.Access, "token_type": "Bearer", "expires_in": s.store.ExpiresInFor(sess), "scope": claims.Scopes(),
		"session_id": sess.ID, "expires_at": sess.MaxDeadline.UTC().Format(time.RFC3339), "template_id": sess.Template,
		"policy_revision_id": sess.PolicyRevision, "observation_policy_id": nil}
	if sess.ObservationPolicy != "" {
		resp["observation_policy_id"] = sess.ObservationPolicy // FR-2.4
	}
	if tok.Refresh != "" {
		resp["refresh_token"] = tok.Refresh
	}
	return resp
}

const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

func newUserCode() string {
	var b strings.Builder
	for i := range 8 {
		if i == 4 {
			b.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			panic(err)
		}
		b.WriteByte(userCodeAlphabet[n.Int64()])
	}
	return b.String()
}

func normalizeUserCode(c string) string {
	c = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(c), " ", ""))
	if len(c) == 8 && !strings.Contains(c, "-") {
		c = c[:4] + "-" + c[4:]
	}
	return c
}

// RFC 8628 section 3.1: device authorization request.
func (s *Service) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	c, ok := s.clientAuth(w, r)
	if !ok {
		return
	}
	if !c.allowsGrant(grantDevice) {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "client is not registered for the device_code grant")
		return
	}
	scope := r.PostForm.Get("scope")
	claims, err := session.ParseScopes(strings.Fields(scope))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	device := ids.Secret()
	s.oauth.mu.Lock()
	if len(s.oauth.devices) >= maxDevices {
		s.oauth.mu.Unlock()
		oauthError(w, http.StatusTooManyRequests, "slow_down", "too many outstanding device authorizations")
		return
	}
	user := newUserCode()
	for s.oauth.users[user] != "" {
		user = newUserCode()
	}
	key := sum(device)
	s.oauth.devices[key] = &deviceGrant{clientID: c.id, principal: c.principal, userCode: user, scope: scope, claims: claims,
		expires: s.now().Add(deviceLifetime), status: "pending"}
	s.oauth.users[user] = key
	s.oauth.mu.Unlock()
	verify := s.publicURL() + pathDevice
	writeJSON(w, http.StatusOK, map[string]any{"device_code": device, "user_code": user, "verification_uri": verify,
		"verification_uri_complete": verify + "?user_code=" + url.QueryEscape(user), "expires_in": int(deviceLifetime.Seconds()), "interval": int(deviceInterval.Seconds())})
}

func (s *Service) deviceByUser(code string) (deviceGrant, bool) {
	s.oauth.mu.Lock()
	defer s.oauth.mu.Unlock()
	key := s.oauth.users[normalizeUserCode(code)]
	d := s.oauth.devices[key]
	if d == nil || s.now().After(d.expires) || d.status != "pending" {
		return deviceGrant{}, false
	}
	return *d, true
}

func (s *Service) deviceData(code string, d *deviceGrant, errMsg string) map[string]any {
	data := map[string]any{"Lead": "Enter the code the agent shows, then sign in as a Session Approver to give it a Gateway session.",
		"Action": pathDevice, "AskCode": true, "UserCode": normalizeUserCode(code), "Error": errMsg, "Hidden": map[string]string{}}
	if d != nil {
		data["ClientID"], data["Principal"], data["Scope"] = d.clientID, d.principal, d.scope
		data["Template"] = session.TemplateLabel(d.scope)
		if g, ok := s.reg.get(d.clientID); ok {
			data["ClientName"] = g.ClientName
		}
	} else {
		data["ClientID"], data["Principal"], data["Template"] = "(enter the code)", "-", "-"
	}
	return data
}

func (s *Service) deviceGET(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("user_code")
	var dp *deviceGrant
	if d, ok := s.deviceByUser(code); ok {
		dp = &d
	}
	s.renderSignin(w, r, http.StatusOK, s.deviceData(code, dp, ""))
}

// devicePOST is the user-interaction step of RFC 8628 section 3.3: a
// Session Approver approves or denies the code.
func (s *Service) devicePOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("user_code")
	d, ok := s.deviceByUser(code)
	account := d.clientID
	if !ok {
		account = "device-code"
	}
	user := r.PostForm.Get("username")
	if s.approverLocked(r, account, user) {
		s.renderSignin(w, r, http.StatusTooManyRequests, s.deviceData(code, nil, "Too many failed attempts. Try again later."))
		return
	}
	if !ok {
		s.fail(r, account, "DEVICE_CODE_UNKNOWN")
		s.renderSignin(w, r, http.StatusBadRequest, s.deviceData(code, nil, "That code is unknown or expired."))
		return
	}
	good, err := s.verifyApprover(r.Context(), user, r.PostForm.Get("password"))
	if err != nil {
		s.renderSignin(w, r, http.StatusServiceUnavailable, s.deviceData(code, &d, "Sign-in is busy. Try again in a moment."))
		return
	}
	if !good {
		s.approverFailed(r, d.clientID, user)
		s.renderSignin(w, r, http.StatusUnauthorized, s.deviceData(code, &d, "Sign-in failed."))
		return
	}
	s.approvers.Success(approverAccount(user))
	decision := "approved"
	if r.PostForm.Get("decision") == "deny" {
		decision = "denied"
	}
	s.oauth.mu.Lock()
	if g := s.oauth.devices[s.oauth.users[normalizeUserCode(code)]]; g != nil && g.status == "pending" {
		g.status, g.approver = decision, user
	}
	s.oauth.mu.Unlock()
	_ = s.commit(r.Context(), audit.Event{Class: "device_authorization", Origin: "E-03", Outcome: decision, ReasonCode: "DEVICE_" + strings.ToUpper(decision), ClientID: d.clientID,
		Detail: map[string]any{"approver": user}})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	session.SecurityHeaders(w.Header())
	fmt.Fprintf(w, "<!doctype html><title>Secure MCP Gateway</title><p>The request was %s. You can close this page.</p>", template.HTMLEscapeString(decision))
}

// devicePoll is the RFC 8628 section 3.4 token request.
func (s *Service) devicePoll(w http.ResponseWriter, r *http.Request, c rclient) {
	key := sum(r.PostForm.Get("device_code"))
	now := s.now()
	s.oauth.mu.Lock()
	d := s.oauth.devices[key]
	if d == nil || d.clientID != c.id {
		s.oauth.mu.Unlock()
		oauthError(w, http.StatusBadRequest, "invalid_grant", "device code unknown or issued to another client")
		return
	}
	if now.After(d.expires) {
		delete(s.oauth.devices, key)
		delete(s.oauth.users, d.userCode)
		s.oauth.mu.Unlock()
		oauthError(w, http.StatusBadRequest, "expired_token", "the device code expired")
		return
	}
	switch d.status {
	case "pending":
		slow := !d.lastPoll.IsZero() && now.Sub(d.lastPoll) < deviceInterval
		d.lastPoll = now
		s.oauth.mu.Unlock()
		if slow {
			oauthError(w, http.StatusBadRequest, "slow_down", "poll no more often than every 5 seconds")
			return
		}
		oauthError(w, http.StatusBadRequest, "authorization_pending", "waiting for a Session Approver to approve the code")
		return
	case "denied":
		delete(s.oauth.devices, key)
		delete(s.oauth.users, d.userCode)
		s.oauth.mu.Unlock()
		oauthError(w, http.StatusBadRequest, "access_denied", "the Session Approver denied the request")
		return
	}
	g := *d
	delete(s.oauth.devices, key)
	delete(s.oauth.users, d.userCode)
	s.oauth.mu.Unlock()
	_ = s.issue(w, r, c, g.principal, g.claims, g.approver, "DEVICE_CODE")
}
