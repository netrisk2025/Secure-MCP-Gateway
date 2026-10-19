package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var (
	itestOnce   sync.Once
	itestClient string
	itestErr    error
)

// buildItestClient builds scripts/itest-client, the scripted MCP client
// that signs in through the OAuth form and calls one tool.
func buildItestClient(t *testing.T) string {
	t.Helper()
	itestOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			itestErr = err
			return
		}
		itestClient = filepath.Join(binDir, "itest-client")
		out, err := exec.Command(goTool, "build", "-o", itestClient, "../../scripts/itest-client").CombinedOutput()
		if err != nil {
			itestErr = err
			t.Logf("%s", out)
		}
	})
	if itestErr != nil {
		t.Fatalf("build itest-client: %v", itestErr)
	}
	return itestClient
}

// healthElements returns info.elements of `smcpctl health` as id -> state.
func healthElements(t *testing.T, cfg string) (map[string]string, map[string]any) {
	t.Helper()
	out := mustCtl(t, "health", "--config", cfg)
	_, body, ok := strings.Cut(out, "\n")
	if !ok {
		t.Fatalf("health output: %s", out)
	}
	var st struct {
		Info struct {
			Elements []struct{ ID, Name, State, Detail string } `json:"elements"`
		} `json:"info"`
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("health JSON: %v\n%s", err, body)
	}
	_ = json.Unmarshal([]byte(body), &raw)
	m := map[string]string{}
	for _, e := range st.Info.Elements {
		m[e.ID] = e.State
	}
	return m, raw
}

// journalEvents reads every event of the journal.
func journalEvents(t *testing.T, stateDir string) []map[string]any {
	t.Helper()
	segs, _ := filepath.Glob(filepath.Join(stateDir, "journal", "segment-*.jsonl"))
	var out []map[string]any
	for _, s := range segs {
		f, err := os.Open(s)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<22)
		for sc.Scan() {
			var e map[string]any
			if json.Unmarshal(sc.Bytes(), &e) == nil && e["type"] == "event" {
				out = append(out, e)
			}
		}
		f.Close()
	}
	return out
}

func detailOf(e map[string]any) map[string]any { d, _ := e["detail"].(map[string]any); return d }

// TestDaemonWiresEveryElement builds the real smcpd from a bootstrap
// configuration, turns on the elements that need setup (Egress Broker,
// Secret Vault), and proves each wired element is live: the health report
// lists it as active, the metrics endpoint serves the approval gauge, a
// call with a credential in its arguments is refused by the request
// filters before dispatch, and an approval-obligated call is held, appears
// in the pending gauge, and is released by `smcpctl approvals approve`.
func TestDaemonWiresEveryElement(t *testing.T) {
	reqtest.Partial(t, "FR-7.12", "FR-3.20", "SR-5.8-1")
	client := buildItestClient(t)
	dir := t.TempDir()
	priv := t.TempDir()
	approverPassword := "approver password 1"
	metricsPort := freePort(t)
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", writeFile(t, priv, "a", "admin password 12\n"),
		"--approver-password-file", writeFile(t, priv, "b", approverPassword+"\n"), "--refserver", filepath.Join(binDir, "smcp-refserver"),
		"--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", metricsPort, "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	raw, _ := os.ReadFile(cfgPath)
	for _, want := range []string{"[approvals]\nnotify = \"off\"", "[metrics]\nenabled = true", "#   [egress]", "#   [secrets]", "#   [graph]"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("bootstrap configuration lacks %q", want)
		}
	}
	// Elements that need setup: the Egress Broker and the Secret Vault.
	if err := os.WriteFile(filepath.Join(dir, "secret-use.json"), []byte(`{"revision": "u1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pp := writeFile(t, priv, "vault-pass", "vault passphrase for tests\n")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("\n[egress]\nenabled = true\n\n[secrets]\nkey_source = \"passphrase\"\npassphrase_file = " + quote(pp) + "\nuse_policy_file = \"secret-use.json\"\n")
	f.Close()
	mustCtl(t, "config", "validate", "--config", cfgPath)
	mustCtl(t, "secrets", "init", "--config", cfgPath)
	if err := os.WriteFile(filepath.Join(dir, "sandbox", "hello.txt"), []byte("wired-marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	d, logs := startDaemonWithLogs(t, cfgPath)
	elements, _ := healthElements(t, cfgPath)
	for _, id := range []string{"E-01/E-02/E-08/E-12", "E-03/E-04", "E-05/E-06", "E-07", "E-09/E-11", "E-10", "E-13/E-14", "E-18", "E-19/E-20",
		"E-21", "E-22", "E-23", "E-24", "E-27/E-29-E-32"} {
		if elements[id] != "active" {
			t.Errorf("element %s is %q, want active (%v)", id, elements[id], elements)
		}
	}
	// Optional elements without their prerequisites are reported, not
	// silently missing: the sandbox needs Linux and Podman, the graph
	// mirror a Neo4j database, remote access a tunnel.
	for _, id := range []string{"E-15/E-16/E-17", "E-25/E-26/E-28", "E-33"} {
		if elements[id] != "disabled" {
			t.Errorf("element %s is %q, want disabled", id, elements[id])
		}
	}
	if t.Failed() {
		stopDaemon(t, d)
		t.Fatalf("smcpd log:\n%s", logs.String())
	}

	metrics := func() string {
		t.Helper()
		resp, err := http.Get("http://127.0.0.1:" + metricsPort + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if m := metrics(); !strings.Contains(m, "smcp_pending_approvals 0") {
		t.Fatalf("metrics:\n%s", m)
	}

	run := func(args ...string) *exec.Cmd {
		base := []string{"-url", "https://127.0.0.1:" + strings.TrimPrefix(publicPort(t, string(raw)), ":"), "-ca", filepath.Join(dir, "state", "tls", "ca.crt"),
			"-password", approverPassword, "-timeout", "90s"}
		return exec.Command(client, append(base, args...)...)
	}
	// E-09: a credential in the arguments is refused before dispatch.
	if out, err := run("-call", "ref_echo", "-args", `{"text":"key AKIAIOSFODNN7EXAMPLE"}`).CombinedOutput(); err == nil {
		t.Fatalf("a call carrying an AWS key was not refused:\n%s", out)
	}
	// E-07: the approval-demo template obliges approval for read_file; the
	// call is held until it is approved.
	held := run("-scope", "smcp:template:approval-demo", "-call", "ref_read_file", "-args", `{"path":"hello.txt"}`, "-expect", "wired-marker")
	var heldOut bytes.Buffer
	held.Stdout, held.Stderr = &heldOut, &heldOut
	if err := held.Start(); err != nil {
		t.Fatal(err)
	}
	heldDone := make(chan error, 1)
	go func() { heldDone <- held.Wait() }()
	idRE := regexp.MustCompile(`"id":\s*"([^"]+)"`)
	var approvalID string
	deadline := time.Now().Add(60 * time.Second)
	for approvalID == "" {
		if m := idRE.FindStringSubmatch(mustCtl(t, "approvals", "list", "--state", "pending", "--json", "--config", cfgPath)); m != nil {
			approvalID = m[1]
			break
		}
		select {
		case err := <-heldDone:
			t.Fatalf("the approval-obligated call ended without being held: %v\n%s", err, heldOut.String())
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pending approval\n%s", heldOut.String())
		}
	}
	if m := metrics(); !strings.Contains(m, "smcp_pending_approvals 1") {
		t.Fatalf("pending approval not in metrics:\n%s", m)
	}
	mustCtl(t, "approvals", "approve", approvalID, "--yes", "--config", cfgPath)
	select {
	case err := <-heldDone:
		if err != nil {
			t.Fatalf("approved call: %v\n%s", err, heldOut.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("the approved call did not return\n%s", heldOut.String())
	}
	stopDaemon(t, d)
	if !strings.Contains(logs.String(), `msg=element`) {
		t.Fatal("smcpd did not log its elements at startup")
	}
	if out := mustCtl(t, "journal", "verify", "--config", cfgPath); !strings.Contains(out, "journal OK") {
		t.Fatal(out)
	}

	evs := journalEvents(t, filepath.Join(dir, "state"))
	var secretRefused, approvalSeen bool
	approvals := map[string]bool{}
	refusedCorr := ""
	for _, e := range evs {
		if e["class"] == "filter" && e["phase"] == "filtered" && e["reason_code"] == "SECRET_IN_ARGUMENTS" {
			secretRefused, refusedCorr = true, e["correlation_id"].(string)
		}
		if e["class"] == "approval" && detailOf(e)["approval_id"] == approvalID {
			approvals[e["outcome"].(string)] = true
			approvalSeen = true
		}
	}
	if !secretRefused {
		t.Fatal("no SECRET_IN_ARGUMENTS refusal in the journal")
	}
	for _, e := range evs {
		if e["correlation_id"] == refusedCorr && e["phase"] == "dispatched" {
			t.Fatal("the refused call was dispatched")
		}
	}
	if !approvalSeen || !approvals["requested"] || !approvals["approved"] || !approvals["consumed"] {
		t.Fatalf("approval events: %v", approvals)
	}
}

// publicPort returns the harness port of a bootstrap configuration.
func publicPort(t *testing.T, cfg string) string {
	t.Helper()
	m := regexp.MustCompile(`public_url = "https://127\.0\.0\.1:(\d+)"`).FindStringSubmatch(cfg)
	if m == nil {
		t.Fatalf("no public_url in\n%s", cfg)
	}
	return m[1]
}
