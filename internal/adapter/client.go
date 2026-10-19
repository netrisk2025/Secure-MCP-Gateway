package adapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Version is the adapter version sent as harness_version.
var Version = "dev"

// NewHTTPClient returns an HTTP client for the Gateway: TLS 1.3, trusting
// only the configured Gateway CA when one is named. The UDS harness socket
// does not speak HTTP; smcp-stdio uses RunUDS for it.
func NewHTTPClient(g GatewaySection) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS13}
	if g.CAFile != "" {
		pem, err := os.ReadFile(g.CAFile)
		if err != nil {
			return nil, fmt.Errorf("gateway CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gateway CA %s: no certificate", g.CAFile)
		}
		tc.RootCAs = pool
	}
	tr := &http.Transport{TLSClientConfig: tc, MaxIdleConnsPerHost: 8, IdleConnTimeout: 60 * time.Second}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// TokenSource supplies the bearer token for Gateway requests.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	// Invalidate drops the current access token after a 401 so that the
	// next Token call refreshes or recreates the session.
	Invalidate()
}

// Session obtains and refreshes a Gateway session for the credential file
// (F-94): the refresh-token grant at the token endpoint (FR-2.20, FR-2.22)
// when a refresh token is held, otherwise the session API (FR-2.2) with the
// client secret. Tokens are written back to the credential file.
type Session struct {
	Creds *Credentials
	HTTP  *http.Client
	Now   func() time.Time
	// TokenURL overrides the token endpoint (remote access discovers it).
	TokenURL string

	mu sync.Mutex
}

// NewSession builds a session over loaded credentials.
func NewSession(c *Credentials) (*Session, error) {
	if c.Gateway.URL == "" {
		return nil, fmt.Errorf("%s: [gateway] url is not set", c.Path())
	}
	h, err := NewHTTPClient(c.Gateway)
	if err != nil {
		return nil, err
	}
	return &Session{Creds: c, HTTP: h, Now: time.Now}, nil
}

// Origin returns scheme://host of the Gateway URL.
func Origin(mcpURL string) (string, error) {
	u, err := url.Parse(mcpURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("gateway url %q is not an absolute URL", mcpURL)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("gateway url %q must use https", mcpURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// OAuthError is an OAuth error response.
type OAuthError struct {
	Status      int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s (HTTP %d)", e.Code, e.Description, e.Status)
	}
	return fmt.Sprintf("%s (HTTP %d)", e.Code, e.Status)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	SessionID    string `json:"session_id"`
}

func decodeToken(resp *http.Response) (tokenResponse, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, err
	}
	if resp.StatusCode/100 != 2 {
		oe := &OAuthError{Status: resp.StatusCode}
		if json.Unmarshal(b, oe) != nil || oe.Code == "" {
			oe.Code = "http_error"
			oe.Description = strings.TrimSpace(string(b))
			if len(oe.Description) > 200 {
				oe.Description = oe.Description[:200]
			}
		}
		return tokenResponse{}, oe
	}
	var t tokenResponse
	if err := json.Unmarshal(b, &t); err != nil {
		return t, err
	}
	if t.AccessToken == "" {
		return t, errors.New("token response without access_token")
	}
	return t, nil
}

func (s *Session) store(t tokenResponse) error {
	s.Creds.Session = SessionSection{ID: t.SessionID, AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, IssuedAt: s.Now().UTC(), ExpiresIn: t.ExpiresIn}
	return s.Creds.Save()
}

func (s *Session) tokenURL() (string, error) {
	if s.TokenURL != "" {
		return s.TokenURL, nil
	}
	o, err := Origin(s.Creds.Gateway.URL)
	if err != nil {
		return "", err
	}
	return o + "/oauth/token", nil
}

// Refresh runs the refresh-token grant.
func (s *Session) Refresh(ctx context.Context) error {
	tu, err := s.tokenURL()
	if err != nil {
		return err
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.Creds.Session.RefreshToken}}
	if s.Creds.Client.Secret == "" {
		form.Set("client_id", s.Creds.Client.ID)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", tu, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.Creds.Client.Secret != "" {
		req.SetBasicAuth(s.Creds.Client.ID, s.Creds.Client.Secret)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	t, err := decodeToken(resp)
	if err != nil {
		return err
	}
	return s.store(t)
}

// Create runs the session API with the client secret (FR-2.2).
func (s *Session) Create(ctx context.Context) error {
	if s.Creds.Client.ID == "" || s.Creds.Client.Secret == "" {
		return fmt.Errorf("%s: no valid session and no [client] id and secret to create one", s.Creds.Path())
	}
	o, err := Origin(s.Creds.Gateway.URL)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"client_id": s.Creds.Client.ID, "client_secret": s.Creds.Client.Secret, "harness_version": "smcp-adapter/" + Version,
		"template_id": s.Creds.Client.Template, "purpose": s.Creds.Client.Purpose, "project_root": s.Creds.Client.Project, "end_user": s.Creds.Client.EndUser})
	req, err := http.NewRequestWithContext(ctx, "POST", o+"/smcp/v1/sessions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	t, err := decodeToken(resp)
	if err != nil {
		return err
	}
	return s.store(t)
}

// Token returns a usable access token, refreshing at half its lifetime and
// creating a new session when refresh is not possible.
func (s *Session) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Creds.Session.fresh(s.Now()) {
		return s.Creds.Session.AccessToken, nil
	}
	var refreshErr error
	if s.Creds.Session.RefreshToken != "" {
		if refreshErr = s.Refresh(ctx); refreshErr == nil {
			return s.Creds.Session.AccessToken, nil
		}
		s.Creds.Session = SessionSection{}
	}
	if s.Creds.Client.Secret == "" {
		if refreshErr != nil {
			return "", fmt.Errorf("session refresh failed (%w); sign in again", refreshErr)
		}
		return "", fmt.Errorf("%s: no session; sign in first", s.Creds.Path())
	}
	if err := s.Create(ctx); err != nil {
		return "", err
	}
	return s.Creds.Session.AccessToken, nil
}

// Invalidate implements TokenSource.
func (s *Session) Invalidate() {
	s.mu.Lock()
	s.Creds.Session.AccessToken = ""
	s.mu.Unlock()
}

// Headers returns the request headers a header helper prints (FR-12.12).
func (s *Session) Headers(ctx context.Context) (map[string]string, error) {
	tok, err := s.Token(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"Authorization": "Bearer " + tok}, nil
}
