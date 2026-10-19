package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Metadata is the subset of RFC 8414 authorization-server metadata the
// adapter uses.
type Metadata struct {
	Issuer                      string `json:"issuer"`
	TokenEndpoint               string `json:"token_endpoint"`
	RegistrationEndpoint        string `json:"registration_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

func getJSON(ctx context.Context, h *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	resp, err := h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// Discover reads the protected-resource metadata of the MCP URL (RFC 9728)
// and the metadata of its authorization server (RFC 8414). The
// authorization server must be on the same origin as the MCP endpoint: the
// relay never sends credentials to another host.
func Discover(ctx context.Context, h *http.Client, mcpURL string) (Metadata, error) {
	origin, err := Origin(mcpURL)
	if err != nil {
		return Metadata{}, err
	}
	u, _ := url.Parse(mcpURL)
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := getJSON(ctx, h, origin+"/.well-known/oauth-protected-resource"+u.Path, &prm); err != nil {
		return Metadata{}, fmt.Errorf("protected resource metadata: %w", err)
	}
	if len(prm.AuthorizationServers) == 0 || strings.TrimSuffix(prm.AuthorizationServers[0], "/") != origin {
		return Metadata{}, fmt.Errorf("authorization server %v is not the Gateway origin %s", prm.AuthorizationServers, origin)
	}
	var md Metadata
	if err := getJSON(ctx, h, origin+"/.well-known/oauth-authorization-server", &md); err != nil {
		return Metadata{}, fmt.Errorf("authorization server metadata: %w", err)
	}
	for _, e := range []string{md.TokenEndpoint, md.RegistrationEndpoint, md.DeviceAuthorizationEndpoint} {
		if e != "" && !strings.HasPrefix(e, origin+"/") {
			return Metadata{}, fmt.Errorf("endpoint %s is not on the Gateway origin", e)
		}
	}
	if md.TokenEndpoint == "" || md.DeviceAuthorizationEndpoint == "" {
		return Metadata{}, errors.New("the Gateway does not offer the device authorization grant (is remote access enabled?)")
	}
	return md, nil
}

func postForm(ctx context.Context, h *http.Client, u string, form url.Values, id, secret string) (*http.Response, error) {
	if secret == "" && id != "" {
		form.Set("client_id", id)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(id, secret)
	}
	return h.Do(req)
}

// Login is the smcp-connect sign-in (FR-16.9): register the relay as a
// public client when the credential file names none (the registration
// waits for operator approval, FR-16.5), then run the RFC 8628 device
// authorization grant; a Session Approver approves the code in a browser.
// Progress and the code are written to prompt (standard error).
type Login struct {
	Creds  *Credentials
	HTTP   *http.Client
	Prompt io.Writer
	Scope  string
	Name   string // client_name for registration
	// Wait bounds the whole sign-in (default 30 minutes).
	Wait time.Duration
	// Sleep replaces time.Sleep (tests).
	Sleep func(context.Context, time.Duration) error
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run signs in and stores the tokens.
func (l *Login) Run(ctx context.Context) (Metadata, error) {
	if l.Wait == 0 {
		l.Wait = 30 * time.Minute
	}
	if l.Sleep == nil {
		l.Sleep = sleepCtx
	}
	ctx, cancel := context.WithTimeout(ctx, l.Wait)
	defer cancel()
	md, err := Discover(ctx, l.HTTP, l.Creds.Gateway.URL)
	if err != nil {
		return md, err
	}
	if l.Creds.Client.ID == "" {
		if err := l.register(ctx, md); err != nil {
			return md, err
		}
	}
	pendingShown := false
	for {
		resp, err := postForm(ctx, l.HTTP, md.DeviceAuthorizationEndpoint, url.Values{"scope": {l.Scope}}, l.Creds.Client.ID, l.Creds.Client.Secret)
		if err != nil {
			return md, err
		}
		var da struct {
			DeviceCode              string `json:"device_code"`
			UserCode                string `json:"user_code"`
			VerificationURI         string `json:"verification_uri"`
			VerificationURIComplete string `json:"verification_uri_complete"`
			ExpiresIn               int    `json:"expires_in"`
			Interval                int    `json:"interval"`
			OAuthError
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&da)
		resp.Body.Close()
		if err != nil {
			return md, fmt.Errorf("device authorization: %w", err)
		}
		if resp.StatusCode == http.StatusUnauthorized && strings.Contains(da.Description, "pending operator approval") {
			if !pendingShown {
				fmt.Fprintf(l.Prompt, "smcp-connect: client %s is waiting for operator approval. On the Gateway host run:\n  smcpctl clients approve %s\n", l.Creds.Client.ID, l.Creds.Client.ID)
				pendingShown = true
			}
			if err := l.Sleep(ctx, 10*time.Second); err != nil {
				return md, err
			}
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			if err := l.Sleep(ctx, 10*time.Second); err != nil {
				return md, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			da.Status = resp.StatusCode
			return md, fmt.Errorf("device authorization: %w", &da.OAuthError)
		}
		fmt.Fprintf(l.Prompt, "smcp-connect: to sign in, open %s and enter the code %s\n  (or open %s)\n", da.VerificationURI, da.UserCode, da.VerificationURIComplete)
		interval := time.Duration(max(da.Interval, 5)) * time.Second
		done, err := l.poll(ctx, md, da.DeviceCode, interval)
		if err != nil {
			return md, err
		}
		if done {
			fmt.Fprintln(l.Prompt, "smcp-connect: signed in")
			return md, nil
		}
		fmt.Fprintln(l.Prompt, "smcp-connect: the code expired; requesting a new one")
	}
}

// poll returns true when tokens were stored, false when the code expired.
func (l *Login) poll(ctx context.Context, md Metadata, device string, interval time.Duration) (bool, error) {
	for {
		if err := l.Sleep(ctx, interval); err != nil {
			return false, err
		}
		resp, err := postForm(ctx, l.HTTP, md.TokenEndpoint, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {device}},
			l.Creds.Client.ID, l.Creds.Client.Secret)
		if err != nil {
			return false, err
		}
		t, err := decodeToken(resp)
		var oe *OAuthError
		switch {
		case err == nil:
			l.Creds.Session = SessionSection{ID: t.SessionID, AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, IssuedAt: time.Now().UTC(), ExpiresIn: t.ExpiresIn}
			return true, l.Creds.Save()
		case errors.As(err, &oe) && oe.Code == "authorization_pending":
		case errors.As(err, &oe) && (oe.Code == "slow_down" || oe.Status == http.StatusTooManyRequests):
			// RFC 8628 slow_down, or the remote listener's rate limit.
			interval += 5 * time.Second
		case errors.As(err, &oe) && oe.Code == "expired_token":
			return false, nil
		default:
			return false, err
		}
	}
}

func (l *Login) register(ctx context.Context, md Metadata) error {
	if md.RegistrationEndpoint == "" {
		return errors.New("no client ID in the credential file and the Gateway offers no registration endpoint; ask the operator for a pre-registered client")
	}
	name := l.Name
	if name == "" {
		host, _ := os.Hostname()
		name = "smcp-connect on " + host
	}
	body, _ := json.Marshal(map[string]any{"client_name": name, "grant_types": []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		"token_endpoint_auth_method": "none", "software_id": "smcp-connect", "software_version": Version})
	req, err := http.NewRequestWithContext(ctx, "POST", md.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		ClientID string `json:"client_id"`
		OAuthError
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return fmt.Errorf("registration: %w", err)
	}
	if resp.StatusCode != http.StatusCreated || out.ClientID == "" {
		out.Status = resp.StatusCode
		return fmt.Errorf("registration: %w", &out.OAuthError)
	}
	l.Creds.Client.ID = out.ClientID
	if err := l.Creds.Save(); err != nil {
		return err
	}
	fmt.Fprintf(l.Prompt, "smcp-connect: registered as client %s\n", out.ClientID)
	return nil
}
