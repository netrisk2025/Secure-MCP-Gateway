package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEgressCommands runs smcpd with the Egress Broker enabled, sends one
// granted and one ungranted request through the reference server's proxy
// and reads the result back with smcpctl egress.
func TestEgressCommands(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "dest-ok") }))
	defer dest.Close()
	du, _ := url.Parse(dest.URL)

	dir := t.TempDir()
	secrets := t.TempDir()
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", writeFile(t, secrets, "a", "admin password 12"),
		"--approver-password-file", writeFile(t, secrets, "b", "approver password 1"),
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The grant names an unpackaged server: the packaged reference server's
	// manifest declares no egress, so a grant for it would keep it from
	// starting (library.CheckEgressCeiling). The test process stands in for
	// the instance and holds no per-call capabilities, so they are off here
	// (internal/egress and the AT-10 acceptance test cover them).
	fmt.Fprintf(f, "\n[[server]]\nalias = \"web\"\ncommand = %q\n\n[egress]\nenabled = true\nrequire_capability = false\n"+
		"[[egress.grant]]\nserver = \"web\"\nhost = \"127.0.0.1\"\nports = [%s]\nmethods = [\"GET\"]\naddresses = [\"127.0.0.1\"]\n",
		filepath.Join(binDir, "smcp-refserver"), du.Port())
	f.Close()
	mustCtl(t, "config", "validate", "--config", cfgPath)
	d := startDaemon(t, cfgPath)

	out := mustCtl(t, "egress", "status", "--config", cfgPath)
	var st struct {
		Advisory  int `json:"advisory_instances"`
		Instances []struct {
			Server, Proxy string
		} `json:"instances"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Advisory != 2 || len(st.Instances) != 2 {
		t.Fatalf("status %v: %s", err, out)
	}
	proxy := ""
	for _, in := range st.Instances {
		if in.Server == "web" {
			proxy = in.Proxy
		}
	}
	if proxy == "" {
		t.Fatalf("no instance of web: %s", out)
	}
	pu, _ := url.Parse(proxy)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := c.Get(dest.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "dest-ok" {
		t.Fatalf("brokered GET: %d %q", resp.StatusCode, b)
	}
	resp, err = c.Get("http://10.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ungranted: %d", resp.StatusCode)
	}

	if out := mustCtl(t, "egress", "grants", "--config", cfgPath, "--server", "web"); !strings.Contains(out, `"host": "127.0.0.1"`) {
		t.Fatal(out)
	}
	var conns string
	for range 50 {
		conns = mustCtl(t, "egress", "connections", "--config", cfgPath)
		if strings.Count(conns, `"id"`) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(conns, `"decision": "allowed"`) || !strings.Contains(conns, "EGRESS_NO_GRANT") {
		t.Fatal(conns)
	}
	if out := mustCtl(t, "egress", "connections", "--config", cfgPath, "--denied", "--limit", "5"); strings.Contains(out, `"decision": "allowed"`) {
		t.Fatal(out)
	}
	if out, err := ctl(t, "", "egress", "bogus", "--config", cfgPath); err == nil || !strings.Contains(out, "usage: smcpctl egress") {
		t.Fatalf("%v %s", err, out)
	}
	stopDaemon(t, d)
	if out := mustCtl(t, "journal", "verify", "--config", cfgPath); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}
}
