package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestStandaloneLabelInEveryPlace is FR-13.10: a Standalone installation
// with every other dependency healthy reports health `degraded` with
// `unconfined` as its only cause, and shows the label `not enforced` in
// `smcpctl health`, in `smcpctl version`, in the health document the
// console's status strip renders (GET /admin/v1/health, field
// release_label, shown by console/src/App.tsx) and in the startup entry of
// the diagnostic log.
func TestStandaloneLabelInEveryPlace(t *testing.T) {
	reqtest.Verifies(t, "FR-13.10")
	_, cfgPath := instance(t)
	d, logs := startDaemonWithLogs(t, cfgPath)

	out := mustCtl(t, "health", "--config", cfgPath)
	if !strings.HasPrefix(out, "health: degraded; causes: unconfined\n") && !strings.HasPrefix(out, "health: degraded; causes: unconfined;") {
		t.Fatalf("health: %s", out)
	}
	if !strings.Contains(out, "release label: not enforced") {
		t.Fatalf("health lacks the label: %s", out)
	}
	if _, body, ok := strings.Cut(out, "{"); ok {
		var st struct {
			State  string   `json:"state"`
			Causes []string `json:"causes"`
		}
		if err := json.Unmarshal([]byte("{"+body), &st); err == nil && (st.State != "degraded" || len(st.Causes) != 1 || st.Causes[0] != "unconfined") {
			t.Fatalf("health document: %+v", st)
		}
	}
	if out := mustCtl(t, "version", "--config", cfgPath); !strings.Contains(out, "not enforced") {
		t.Fatalf("version: %s", out)
	}

	// The console's status strip reads /admin/v1/health.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := keys.LoadAdminToken(cfg.State.Dir)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if ca, err := os.ReadFile(filepath.Join(cfg.State.Dir, keys.CACertFile)); err == nil {
		pool.AppendCertsFromPEM(ca)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	req, _ := http.NewRequest("GET", cfg.AdminURL()+"/admin/v1/health", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var h map[string]any
	if resp.StatusCode != 200 || json.Unmarshal(b, &h) != nil || h["release_label"] != "not enforced" || h["state"] != "degraded" {
		t.Fatalf("console health: %d %s", resp.StatusCode, b)
	}

	// The startup entry of the diagnostic log, read once the daemon has
	// exited and its output is complete.
	stopDaemon(t, d)
	startup := ""
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "release_label") {
			startup = line
			break
		}
	}
	if !strings.Contains(startup, "not enforced") {
		t.Fatalf("no startup log entry with the label:\n%s", logs.String())
	}
}
