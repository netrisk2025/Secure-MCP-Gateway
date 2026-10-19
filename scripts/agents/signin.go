package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// session is what a completed sign-in yields: the bearer token the agent
// presents to the MCP endpoint and the Gateway's session identifier, which
// keys every journal assertion for that agent.
type session struct {
	Token     string
	SessionID string
	Template  string
}

// signIn runs the OAuth 2.1 authorization-code flow with PKCE (S256) against
// the Gateway's authorization server without a browser: it discovers the
// server from the 401 challenge, fetches the sign-in form, submits the
// Session Approver credentials and reads the code from the redirect to the
// registered loopback callback, as the client's own loopback listener would.
// This is the automation path of FR-2.19: a person (here the suite, holding
// the Session Approver password) approves the sign-in; the agent never sees
// the password.
func signIn(hc *http.Client, endpoint, clientID, redirect, username, password, scope string) (*session, error) {
	resp, err := hc.Post(endpoint, "application/json", strings.NewReader(`{}`))
	if err != nil {
		return nil, err
	}
	drain(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthenticated POST %s: status %d, want 401", endpoint, resp.StatusCode)
	}
	prmURL := challengeParam(resp.Header.Get("WWW-Authenticate"), "resource_metadata")
	if prmURL == "" {
		return nil, fmt.Errorf("401 lacks resource_metadata: %q", resp.Header.Get("WWW-Authenticate"))
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := getJSON(hc, prmURL, &prm); err != nil {
		return nil, err
	}
	if prm.Resource == "" || len(prm.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("protected resource metadata incomplete: %+v", prm)
	}
	var asm struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	}
	if err := getJSON(hc, strings.TrimRight(prm.AuthorizationServers[0], "/")+"/.well-known/oauth-authorization-server", &asm); err != nil {
		return nil, err
	}
	if !contains(asm.CodeChallengeMethods, "S256") {
		return nil, fmt.Errorf("authorization server does not offer S256: %v", asm.CodeChallengeMethods)
	}

	verifier := randomString(48)
	sum := sha256.Sum256([]byte(verifier))
	state := randomString(16)
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"resource": {prm.Resource},
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	authURL, err := url.Parse(asm.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}
	authURL.RawQuery = q.Encode()
	resp, err = hc.Get(authURL.String())
	if err != nil {
		return nil, err
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorization GET: status %d: %s", resp.StatusCode, page)
	}
	action, fields, err := parseForm(string(page))
	if err != nil {
		return nil, err
	}
	fields.Set("username", username)
	fields.Set("password", password)
	actionURL, err := authURL.Parse(action)
	if err != nil {
		return nil, err
	}
	resp, err = hc.PostForm(actionURL.String(), fields)
	if err != nil {
		return nil, err
	}
	drain(resp)
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		return nil, fmt.Errorf("sign-in POST: status %d, want a redirect", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(loc.String(), redirect) {
		return nil, fmt.Errorf("redirected to %s, want %s", loc.Redacted(), redirect)
	}
	cb := loc.Query()
	if e := cb.Get("error"); e != "" {
		return nil, fmt.Errorf("authorization error %s: %s", e, cb.Get("error_description"))
	}
	if cb.Get("state") != state {
		return nil, errors.New("state mismatch in the callback")
	}
	if cb.Get("code") == "" {
		return nil, errors.New("callback has no code")
	}

	resp, err = hc.PostForm(asm.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "code": {cb.Get("code")}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifier}, "resource": {prm.Resource},
	})
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token: status %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		SessionID   string `json:"session_id"`
		TemplateID  string `json:"template_id"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	if tok.AccessToken == "" || tok.SessionID == "" {
		return nil, errors.New("token response lacks access_token or session_id")
	}
	return &session{Token: tok.AccessToken, SessionID: tok.SessionID, Template: tok.TemplateID}, nil
}

func getJSON(hc *http.Client, u string, v any) error {
	resp, err := hc.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

var (
	formRe  = regexp.MustCompile(`(?is)<form[^>]*\baction="([^"]*)"`)
	inputRe = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRe  = regexp.MustCompile(`(?is)\b(type|name|value)="([^"]*)"`)
)

// parseForm returns the form action and its hidden fields.
func parseForm(page string) (string, url.Values, error) {
	m := formRe.FindStringSubmatch(page)
	if m == nil {
		return "", nil, errors.New("authorization page has no form")
	}
	fields := url.Values{}
	for _, in := range inputRe.FindAllString(page, -1) {
		attrs := map[string]string{}
		for _, a := range attrRe.FindAllStringSubmatch(in, -1) {
			attrs[strings.ToLower(a[1])] = html.UnescapeString(a[2])
		}
		if strings.EqualFold(attrs["type"], "hidden") && attrs["name"] != "" {
			fields.Set(attrs["name"], attrs["value"])
		}
	}
	return html.UnescapeString(m[1]), fields, nil
}

// challengeParam extracts a parameter from a WWW-Authenticate header.
func challengeParam(h, name string) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `="([^"]*)"`)
	if m := re.FindStringSubmatch(h); m != nil {
		return m[1]
	}
	return ""
}

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
