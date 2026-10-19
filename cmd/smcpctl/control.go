package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// adminClient talks to the control API with the operator token.
type adminClient struct {
	base  string
	token string
	http  *http.Client
}

func newAdminClient(cfg *config.Config, withToken bool) (*adminClient, error) {
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(cfg.State.Dir, keys.CACertFile))
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("CA certificate unreadable")
	}
	c := &adminClient{base: cfg.AdminURL(), http: &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}}
	if withToken {
		if c.token, err = keys.LoadAdminToken(cfg.State.Dir); err != nil {
			return nil, fmt.Errorf("operator token (run smcpctl as the Gateway's user): %w", err)
		}
	}
	return c, nil
}

// do sends a request and returns the decoded JSON body (nil for 204).
func (c *adminClient) do(method, path string, body any) (map[string]any, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd) //nolint:gosec // G704: the configured loopback control API; callers validate path segments
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req) //nolint:gosec // G704: see NewRequest above
	if err != nil {
		return nil, 0, fmt.Errorf("control API at %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, resp.StatusCode, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("control API returned non-JSON (%d)", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		msg := fmt.Sprint(out["error"])
		if e, ok := out["error"].(map[string]any); ok {
			msg = fmt.Sprintf("%v (%v)", e["message"], e["code"])
		}
		return out, resp.StatusCode, fmt.Errorf("control API: %s", msg)
	}
	return out, resp.StatusCode, nil
}

func printJSON(out io.Writer, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(out, string(b))
}

// control runs one authenticated control API request and prints the result.
func control(args []string, out io.Writer, method, path string, body any) error {
	fs := flag.NewFlagSet(path, flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	res, _, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	if res != nil {
		printJSON(out, res)
	}
	return nil
}

func stopCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	reason := fs.String("reason", "", "reason recorded with the emergency stop")
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return control([]string{"--config", *cfgPath}, out, "POST", "/admin/v1/stop", map[string]any{"reason": *reason})
}

// redeem sets the administrator password with the one-use bootstrap token.
func redeem(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("admin redeem", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	tokenFile := fs.String("token-file", "", "read the bootstrap token from this file (mode 0600 or stricter) instead of a prompt")
	pwFile := fs.String("password-file", "", "read the new administrator password from this file (mode 0600 or stricter) instead of a prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errPasswordArg
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	tok, err := readPassword(*tokenFile, "Bootstrap token", false)
	if err != nil {
		return err
	}
	pw, err := readPassword(*pwFile, "New administrator password", true)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, false)
	if err != nil {
		return err
	}
	if _, _, err := c.do("POST", "/admin/v1/bootstrap", map[string]any{"token": tok, "password": pw}); err != nil {
		return err
	}
	fmt.Fprintln(out, "administrator password set; the bootstrap token is spent")
	return nil
}
