package e2e

// End-to-end tests of the operations runtime (internal/ops): health
// monitor gate, metrics, key rotation under traffic, online backup,
// configuration reload, evidence export and the upgrade marker.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backup"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/health"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/metrics"
	"github.com/ethan03805/secure-mcp-gateway/internal/ops"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type opsFixture struct {
	*fixture
	rt      *ops.Runtime
	mon     *health.Monitor
	cfgPath string
	toml    string
}

// opsConfig is the e2e configuration with extra top-level tables appended.
func opsConfig(t *testing.T, dir, stateDir string, port, adminPort int, extra string) string {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`schema_version = 1
[listener]
address = "127.0.0.1:%d"
public_url = "https://127.0.0.1:%d"
[admin_listener]
address = "127.0.0.1:%d"
[state]
dir = %q
[admin]
username = "admin"
password_hash = %q
[[approver]]
username = "approver"
password_hash = %q
[policy]
file = %q
[limits]
upstream_timeout = "2s"
client_deadline = "3s"
%s
[[principal]]
id = "cc"
framework = "claude-code"
profile = "dev"
[[client]]
client_id = %q
principal = "cc"
redirect_uris = ["http://localhost:*/callback"]
[[server]]
alias = "t"
command = %q
args = ["-test.run=NONE"]
[server.env]
SMCP_E2E_BACKEND = "1"
`, port, port, adminPort, stateDir, mustHash(t, "admin password 12"), mustHash(t, approverPassword), filepath.Join(dir, "policy.json"),
		extra, clientID, exe)
}

// startOps starts a Gateway the way smcpd does: Prepare, a health monitor
// gating the edge, app.Start, ops.Attach. extra is TOML placed after the
// [limits] table (more limits or whole tables).
func startOps(t *testing.T, extra string, setup func(stateDir string)) *opsFixture {
	t.Helper()
	return startOpsWith(t, extra, setup, health.Options{Interval: 200 * time.Millisecond, Recovery: time.Second})
}

// startOpsWith is startOps with the health monitor's options (its log is
// always discarded).
func startOpsWith(t *testing.T, extra string, setup func(stateDir string), hopts health.Options) *opsFixture {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(stateDir)
	}
	port, adminPort := freePort(t), freePort(t)
	body := opsConfig(t, dir, stateDir, port, adminPort, extra)
	cfgPath := filepath.Join(dir, "smcp.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(testPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.Prepare(cfg); err != nil {
		t.Fatal(err)
	}
	hopts.Log = diag.Discard()
	mon := health.New(hopts)
	ctx, cancel := context.WithCancel(context.Background())
	a, err := app.Start(ctx, cfg, app.Options{Log: diag.Discard(), JanitorInterval: 200 * time.Millisecond, HealthGate: mon.Gate})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	rt, err := ops.Attach(ctx, a, ops.Options{ConfigPath: cfgPath, Log: diag.Discard(), Monitor: mon, BackupWorkFactor: 10, KeyInterval: time.Hour})
	if err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	if err := a.Listen(); err != nil {
		cancel()
		a.Close()
		t.Fatal(err)
	}
	f := &fixture{t: t, cfg: cfg, app: a, base: cfg.Listener.PublicURL, stateDir: stateDir, cancel: cancel, served: make(chan error, 1)}
	go func() { f.served <- a.Serve(ctx) }()
	f.client = clientTrusting(t, filepath.Join(stateDir, keys.CACertFile))
	if f.operator, err = keys.LoadAdminToken(stateDir); err != nil {
		t.Fatal(err)
	}
	of := &opsFixture{fixture: f, rt: rt, mon: mon, cfgPath: cfgPath, toml: body}
	t.Cleanup(of.stopAll)
	return of
}

func (o *opsFixture) stopAll() {
	if o.cancel == nil {
		return
	}
	o.rt.Close()
	o.stop()
}

// clientTrusting returns an HTTP client trusting the CAs in a PEM file.
func clientTrusting(t *testing.T, caFile string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	b, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(b)
	return clientWithPool(pool)
}

func clientWithPool(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (o *opsFixture) echo(cs *mcp.ClientSession, text string) error {
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_echo", Arguments: map[string]any{"text": text}})
	if err != nil {
		return err
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); !ok || tc.Text != "echo:"+text {
		return fmt.Errorf("unexpected result %+v", res.Content)
	}
	return nil
}

func (o *opsFixture) mcpWith(hc *http.Client, access string) *mcp.ClientSession {
	o.t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e-harness", Version: "1"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: o.cfg.ResourceURI(),
		HTTPClient: &http.Client{Transport: bearerRT{access, hc.Transport}}}, nil)
	if err != nil {
		o.t.Fatal(err)
	}
	o.t.Cleanup(func() { cs.Close() })
	return cs
}

func journalEvents(t *testing.T, stateDir string) []audit.Event {
	t.Helper()
	evs, err := audit.ReadEvents(filepath.Join(stateDir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestOpsMetricsAndHealthGate(t *testing.T) {
	// FR-17.4: metrics on the loopback address only; FR-17.5: every metric
	// of the set after a test run, with no other label names.
	reqtest.Verifies(t, "FR-17.4", "FR-17.5")
	// SR-7.10-1 with the free-space measurement replaced by a test value;
	// FR-7.11 detection within 2 s and fail-closed for a critical cause;
	// FR-13.10 degraded with unconfined in the Standalone profile.
	reqtest.Partial(t, "SR-7.10-1", "FR-7.11", "FR-7.12", "FR-13.10")
	mport := freePort(t)
	f := startOps(t, fmt.Sprintf("[metrics]\nenabled = true\naddress = \"127.0.0.1:%d\"\n", mport), nil)
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	for i := 0; i < 3; i++ {
		if err := f.echo(cs, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_rpcerror"})

	// Scrape (plain HTTP on loopback).
	var expo string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", mport))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		expo = string(b)
		if strings.Contains(expo, `outcome="delivered",reason_code=""} 3`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, want := range []string{
		`smcp_calls_total{server_alias="t",tool="t_echo",outcome="delivered",reason_code=""} 3`,
		`smcp_calls_total{server_alias="t",tool="t_rpcerror",outcome="failed",reason_code="BACKEND_ERROR"} 1`,
		"smcp_decision_latency_seconds_count", "smcp_journal_flush_seconds_count", "smcp_health_state 1",
		"smcp_active_sessions 1", "smcp_pending_approvals 0", `smcp_backend_instances_running{server_alias="t"} 1`,
	} {
		if !strings.Contains(expo, want) {
			t.Errorf("metrics lack %q\n%s", want, expo)
		}
	}
	allowed := map[string]bool{"le": true}
	for _, l := range metrics.AllowedLabels {
		allowed[l] = true
	}
	for _, line := range strings.Split(expo, "\n") {
		if i := strings.Index(line, "{"); i >= 0 && !strings.HasPrefix(line, "#") {
			for _, kv := range strings.Split(line[i+1:strings.LastIndex(line, "}")], ",") {
				if name, _, _ := strings.Cut(kv, "="); !allowed[name] {
					t.Errorf("label %q not allowed: %s", name, line)
				}
			}
		}
	}
	if _, err := metrics.Listen(fmt.Sprintf("0.0.0.0:%d", freePort(t))); !errors.Is(err, metrics.ErrNotLoopback) {
		t.Fatalf("non-loopback metrics address: %v", err)
	}
	// The control API status: degraded with unconfined (Standalone).
	code, st := f.admin("GET", "/api/v1/health/status", f.operator, nil)
	if code != 200 || st["state"] != "degraded" || !strings.Contains(fmt.Sprint(st["causes"]), "unconfined") {
		t.Fatalf("status %d %v", code, st)
	}
	if info, _ := st["info"].(map[string]any); info["release_label"] != "not enforced" {
		t.Fatalf("label %v", st["info"])
	}

	// Mandatory-audit capacity below the reserve: fail-closed within 2 s.
	restore := health.SetFreeBytes(func(string) (uint64, error) { return 100 << 20, nil })
	t.Cleanup(restore)
	start := time.Now()
	for len(f.mon.Gate()) == 0 {
		if time.Since(start) > 7*time.Second { // the disk check is cached for 5 s
			t.Fatal("capacity stop not detected")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := f.echo(cs, "x"); err == nil {
		t.Fatal("call accepted during the capacity stop")
	}
	status, _, body := f.post(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"x"},`+modernMeta+`}}`,
		modernHeaders(access, "tools/call"))
	if status != http.StatusServiceUnavailable || !strings.Contains(body, fmt.Sprint(edge.CodeGatewayFailClosed)) || !strings.Contains(body, edge.ReasonFailClosed) {
		t.Fatalf("call during capacity stop: %d %s", status, body)
	}
	_, st = f.admin("GET", "/api/v1/health/status", f.operator, nil)
	if st["state"] != "fail-closed" || !strings.Contains(fmt.Sprint(st["causes"]), "audit_capacity") {
		t.Fatalf("status %v", st)
	}
	restore()
	for len(f.mon.Gate()) != 0 {
		if time.Since(start) > 20*time.Second {
			t.Fatal("capacity stop not released")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := f.echo(cs, "after"); err != nil {
		t.Fatalf("call after recovery: %v", err)
	}
}

// bundleFollowingClient returns an HTTP client that opens a new TLS
// connection for every request and trusts, at each handshake, the CAs in
// the extra file and in the published bundle as it is then: a client that
// imports the bundle during a CA overlap.
func bundleFollowingClient(t *testing.T, extra, bundle string) *http.Client {
	t.Helper()
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			pool := x509.NewCertPool()
			for _, f := range []string{extra, bundle} {
				b, err := os.ReadFile(f)
				if err != nil {
					return nil, err
				}
				pool.AppendCertsFromPEM(b)
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := &tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13}}
			return d.DialContext(ctx, network, addr)
		},
	}}
}

func TestOpsKeyRotationUnderTraffic(t *testing.T) {
	// FR-17.7, with calls running throughout on one session over a new TLS
	// connection per request (a client that follows the published bundle)
	// and on a second session over a kept-alive connection: TLS rotation
	// keeps sessions; during the CA overlap clients trusting the outgoing
	// CA and clients trusting the published bundle connect; after the
	// switch clients trusting the incoming CA connect and sessions
	// continue; the evidence key rotation writes a transition record that
	// verifies. Not one call fails across the rotations.
	reqtest.Verifies(t, "FR-17.7", "FR-17.8")
	f := startOps(t, "principal_calls_per_minute = 100000\nprincipal_call_burst = 1000\n", nil)
	oldCAFile := filepath.Join(t.TempDir(), "old-ca.crt")
	b, _ := os.ReadFile(filepath.Join(f.stateDir, keys.CACertFile))
	_ = os.WriteFile(oldCAFile, b, 0o644)
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	if err := f.echo(cs, "before"); err != nil {
		t.Fatal(err)
	}
	// Background traffic until the rotations are done.
	follower := f.mcpWith(bundleFollowingClient(t, oldCAFile, filepath.Join(f.stateDir, keys.CACertFile)), access)
	var (
		trafficMu   sync.Mutex
		trafficErrs []error
		trafficOK   = map[string]int{}
		phase       atomic.Value
	)
	phase.Store("tls")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for name, sess := range map[string]*mcp.ClientSession{"new-connection": follower, "kept-alive": cs} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				err := f.echo(sess, fmt.Sprintf("%s-%d", name, i))
				trafficMu.Lock()
				if err != nil {
					trafficErrs = append(trafficErrs, fmt.Errorf("%s call %d during %v: %w", name, i, phase.Load(), err))
				} else {
					trafficOK[name+"/"+phase.Load().(string)]++
				}
				trafficMu.Unlock()
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	stopTraffic := func() {
		close(stop)
		wg.Wait()
		trafficMu.Lock()
		defer trafficMu.Unlock()
		for _, err := range trafficErrs {
			t.Error(err)
		}
		for _, name := range []string{"new-connection", "kept-alive"} {
			for _, ph := range []string{"tls", "overlap", "switched", "evidence"} {
				if trafficOK[name+"/"+ph] == 0 {
					t.Errorf("no %s call succeeded during %s: %v", name, ph, trafficOK)
				}
			}
		}
	}
	waitCalls := func() { // every traffic session completes calls in the current phase
		ph := phase.Load().(string)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			trafficMu.Lock()
			ok := trafficOK["new-connection/"+ph] > 2 && trafficOK["kept-alive/"+ph] > 2
			trafficMu.Unlock()
			if ok {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitCalls()

	code, res := f.admin("POST", "/api/v1/keys/rotate", f.operator, map[string]any{"kind": "tls"})
	if code != 200 || res["kind"] != "tls" {
		t.Fatalf("rotate tls %d %v", code, res)
	}
	time.Sleep(1100 * time.Millisecond) // the reloader re-reads at most once per second
	fresh := f.mcpWith(clientTrusting(t, oldCAFile), access)
	if err := f.echo(fresh, "new-connection"); err != nil {
		t.Fatalf("session over a new connection after TLS rotation: %v", err)
	}
	if err := f.echo(cs, "same-session"); err != nil {
		t.Fatalf("existing client after TLS rotation: %v", err)
	}

	waitCalls()
	code, res = f.admin("POST", "/api/v1/keys/rotate", f.operator, map[string]any{"kind": "ca", "overlap": "1h"})
	if code != 200 || res["stage"] != "overlap" {
		t.Fatalf("rotate ca %d %v", code, res)
	}
	phase.Store("overlap")
	waitCalls()
	if code, _ := f.admin("POST", "/api/v1/keys/rotate", f.operator, map[string]any{"kind": "ca"}); code != 409 {
		t.Fatalf("second CA rotation: %d", code)
	}
	if err := f.echo(f.mcpWith(clientTrusting(t, oldCAFile), access), "overlap-old-trust"); err != nil {
		t.Fatalf("old-CA client during overlap: %v", err)
	}
	bundleFile := filepath.Join(f.stateDir, keys.CACertFile)
	if err := f.echo(f.mcpWith(clientTrusting(t, bundleFile), access), "overlap-bundle"); err != nil {
		t.Fatalf("bundle client during overlap: %v", err)
	}
	newCA, _ := os.ReadFile(filepath.Join(f.stateDir, keys.CANextCertFile))
	code, res = f.admin("POST", "/api/v1/keys/rotate", f.operator, map[string]any{"kind": "ca", "finish": true})
	if code != 200 || res["stage"] != "finished" {
		t.Fatalf("finish ca %d %v", code, res)
	}
	time.Sleep(1100 * time.Millisecond)
	phase.Store("switched")
	waitCalls()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(newCA)
	if err := f.echo(f.mcpWith(clientWithPool(pool), access), "new-ca"); err != nil {
		t.Fatalf("new-CA client after the switch: %v", err)
	}
	oldOnly := clientTrusting(t, oldCAFile)
	if _, err := oldOnly.Get(f.base + "/healthz"); err == nil {
		t.Fatal("old-CA client still connects after the switch")
	}
	f.client = clientWithPool(pool) // the fixture's admin calls use the new CA

	code, res = f.admin("POST", "/api/v1/keys/rotate", f.operator, map[string]any{"kind": "evidence"})
	if code != 200 || res["public_key"] == "" {
		t.Fatalf("rotate evidence %d %v", code, res)
	}
	phase.Store("evidence")
	if err := f.echo(f.mcpWith(clientWithPool(pool), access), "after-evidence-rotation"); err != nil {
		t.Fatal(err)
	}
	waitCalls()
	stopTraffic()
	if code, _ := f.admin("POST", "/api/v1/keys/rotate", f.operator, map[string]any{"kind": "bogus"}); code != 400 {
		t.Fatalf("bogus kind %d", code)
	}
	_, ks := f.admin("GET", "/api/v1/keys", f.operator, nil)
	if ks["evidence_public_key"] != res["public_key"] || ks["evidence_trust_root"] == ks["evidence_public_key"] {
		t.Fatalf("key status %v", ks)
	}
	f.stopAll()
	root, _ := keys.LoadEvidenceTrustRoot(f.stateDir)
	rep, err := audit.Verify(filepath.Join(f.stateDir, "journal"), root)
	if err != nil || len(rep.Transitions) != 1 || rep.CurrentKey() != res["public_key"] {
		t.Fatalf("journal across the evidence-key rotation: %+v %v", rep, err)
	}
	var kinds []string
	for _, e := range journalEvents(t, f.stateDir) {
		if e.Outcome == "key_rotated" {
			kinds = append(kinds, e.ReasonCode)
		}
	}
	want := "LISTENER_CERT_ROTATED SERVER_CA_ROTATION_STARTED SERVER_CA_ACTIVATED EVIDENCE_KEY_ROTATED EVIDENCE_KEY_ROTATED"
	if strings.Join(kinds, " ") != want {
		t.Fatalf("rotation events %v", kinds)
	}
}

func TestOpsOnlineBackup(t *testing.T) {
	// SR-7.7-1: dispatch stopped, journal sealed, archive written and
	// checksummed, dispatch resumed, in that order in the journal. Under
	// load (in-flight calls during the stop) is not exercised (partial).
	reqtest.Partial(t, "SR-7.7-1", "FR-17.6", "FR-9.16")
	f := startOps(t, "", nil)
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	if err := f.echo(cs, "x"); err != nil {
		t.Fatal(err)
	}
	// No schedule and no backup yet: not configured (FR-8.31 checklist).
	if _, list := f.admin("GET", "/api/v1/backup", f.operator, nil); list["configured"] != false || list["scheduled"] != false {
		t.Fatalf("backup state before any backup: %v", list)
	}
	if code, res := f.admin("POST", "/api/v1/backup", f.operator, map[string]any{}); code != 400 || !strings.Contains(fmt.Sprint(res), "BACKUP_UNENCRYPTED_REFUSED") {
		t.Fatalf("unencrypted backup %d %v", code, res)
	}
	code, res := f.admin("POST", "/api/v1/backup", f.operator, map[string]any{"passphrase": "backup pass"})
	if code != 200 || res["sha256"] == "" {
		t.Fatalf("backup %d %v", code, res)
	}
	if err := f.echo(cs, "after-backup"); err != nil {
		t.Fatalf("dispatch not resumed: %v", err)
	}
	_, list := f.admin("GET", "/api/v1/backup", f.operator, nil)
	if n := len(list["backups"].([]any)); n != 1 || list["configured"] != true { // the refused request wrote nothing
		t.Fatalf("index %v", list)
	}
	// Stopping dispatch first leaves it stopped afterwards.
	f.admin("POST", "/admin/v1/stop", f.operator, map[string]any{"reason": "operator"})
	if code, _ := f.admin("POST", "/api/v1/backup", f.operator, map[string]any{"passphrase": "backup pass"}); code != 200 {
		t.Fatal("backup during emergency stop")
	}
	if !f.app.Gateway.Stopped() {
		t.Fatal("backup lifted an operator's emergency stop")
	}
	path := res["path"].(string)
	f.stopAll()
	var seq []string
	for _, e := range journalEvents(t, f.stateDir) {
		switch e.ReasonCode {
		case "EMERGENCY_STOP", "BACKUP_WRITTEN", "EMERGENCY_RESUME", "BACKUP_UNENCRYPTED_REFUSED":
			seq = append(seq, e.ReasonCode)
		}
	}
	if got := strings.Join(seq, " "); !strings.HasPrefix(got, "BACKUP_UNENCRYPTED_REFUSED EMERGENCY_STOP BACKUP_WRITTEN EMERGENCY_RESUME EMERGENCY_STOP BACKUP_WRITTEN") || strings.HasSuffix(got, "EMERGENCY_RESUME") {
		t.Fatalf("backup sequence %q", got)
	}
	rep, err := backup.Restore(backup.RestoreOptions{Archive: path, Decryption: backup.Decryption{Passphrase: "backup pass"}, StateDir: f.stateDir,
		ConfigPath: f.cfgPath, PolicyPath: f.cfg.Policy.File, VerifyOnly: true})
	if err != nil || rep.JournalEvents == 0 || !rep.Manifest.Has("evidence_journal") || !rep.Manifest.Has("key_material") {
		t.Fatalf("restore verify %+v %v", rep, err)
	}
	// The archive's journal ends with the stop event sealed in it.
	sealed := false
	iso := t.TempDir()
	if _, err := backup.Extract(path, filepath.Join(iso, "x"), backup.Decryption{Passphrase: "backup pass"}); err != nil {
		t.Fatal(err)
	}
	evs, _ := audit.ReadEvents(filepath.Join(iso, "x", "state", "journal"))
	for _, e := range evs {
		sealed = sealed || e.ReasonCode == "EMERGENCY_STOP"
	}
	if !sealed {
		t.Fatal("the stop before the backup is not in the archived journal")
	}
}

func TestOpsConfigReload(t *testing.T) {
	// FR-17.9: an invalid file keeps the running configuration; a changed
	// rate limit (a CP-50 reloadable key) applies with the session intact;
	// a changed listener address and a changed queue bound (not reloadable)
	// are reported as needing a restart.
	reqtest.Verifies(t, "FR-17.9")
	f := startOps(t, "", nil)
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	if err := f.echo(cs, "x"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.cfgPath, []byte("not = [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, res := f.admin("POST", "/api/v1/config/reload", f.operator, map[string]any{}); code != 422 {
		t.Fatalf("invalid reload %d %v", code, res)
	}
	if f.app.Decider.DefaultRate() != 60 {
		t.Fatal("running configuration changed by an invalid reload")
	}
	changed := strings.Replace(f.toml, "client_deadline = \"3s\"", "client_deadline = \"3s\"\nprincipal_calls_per_minute = 2\ntool_queue = 5", 1)
	changed = strings.Replace(changed, f.cfg.Listener.Address+"\"\npublic_url", "127.0.0.1:1\"\npublic_url", 1)
	if err := os.WriteFile(f.cfgPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := f.rt.Reload("test")
	if err != nil {
		t.Fatal(err)
	}
	has := func(list []string, k string) bool {
		for _, x := range list {
			if x == k {
				return true
			}
		}
		return false
	}
	if !has(res.Applied, "limits.principal_calls_per_minute") || !has(res.RestartRequired, "listener.address") || !has(res.RestartRequired, "limits.tool_queue") ||
		len(res.NotApplied) != 0 {
		t.Fatalf("reload result %+v", res)
	}
	if f.app.Decider.DefaultRate() != 2 {
		t.Fatal("new rate limit not applied")
	}
	// The session continues and the new limit applies to it.
	var limited bool
	for i := 0; i < 4 && !limited; i++ {
		if err := f.echo(cs, "y"); err != nil {
			we, data := rpcErr(t, err)
			limited = we.Code == edge.CodeRateLimited || data["reasonCode"] == "RATE_LIMITED"
			if !limited {
				t.Fatalf("unexpected error after reload: %v", err)
			}
		}
	}
	if !limited {
		t.Fatal("the reloaded limit of 2 calls per minute was not enforced")
	}
	// A second reload of the same file reports only the restart-bound key.
	res, _ = f.rt.Reload("test")
	if len(res.Applied) != 0 || !has(res.RestartRequired, "listener.address") {
		t.Fatalf("second reload %+v", res)
	}
	f.stopAll()
	n := 0
	for _, e := range journalEvents(t, f.stateDir) {
		if e.ReasonCode == "CONFIG_RELOADED" || e.ReasonCode == "CONFIG_INVALID" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("reload events %d", n)
	}
}

func TestOpsEvidenceExport(t *testing.T) {
	// FR-7.14: closed segments and the checkpoint are copied to the
	// export directory within 60 s (here within the 1 s interval) and the
	// copies verify.
	reqtest.Verifies(t, "FR-7.14")
	f := startOps(t, "[evidence]\nexport_dir = \"export\"\nexport_interval = \"1s\"\n", nil)
	exportDir := filepath.Join(filepath.Dir(f.cfgPath), "export")
	access, _, _ := f.oauthLogin("")
	cs := f.mcpClient(access)
	_ = f.echo(cs, "x")
	if err := f.app.Journal.Seal(); err != nil {
		t.Fatal(err)
	}
	closedAt := time.Now()
	root, _ := keys.LoadEvidenceTrustRoot(f.stateDir)
	for {
		rep, err := audit.Verify(filepath.Join(exportDir, "journal"), root)
		if err == nil && rep.AnchorSegment >= 1 {
			if rep.Events == 0 {
				t.Fatal("export has no events")
			}
			break
		}
		if time.Since(closedAt) > 5*time.Second {
			t.Fatalf("segment not exported within 5 s: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(exportDir, "keys", "evidence-genesis.pub")); err != nil {
		t.Fatal("public key not exported")
	}
}

func TestOpsUpgradeMarkerRecorded(t *testing.T) {
	// FR-13.8: the previous version records upgrade_rolled_back when it
	// starts after a rollback (the marker written by smcpctl upgrade). The
	// binary swap and restore are tested in cmd/smcpctl and the
	// integration script (partial).
	reqtest.Partial(t, "FR-13.8")
	f := startOps(t, "", func(stateDir string) {
		b, _ := json.Marshal(ops.UpgradeEvent{Outcome: "upgrade_rolled_back", FromVersion: "1.0.0", ToVersion: "1.1.0", Reason: "health", Time: time.Now().UTC().Format(time.RFC3339)})
		_ = os.WriteFile(filepath.Join(stateDir, ops.UpgradeEventFile), b, 0o600)
	})
	f.stopAll()
	found := false
	for _, e := range journalEvents(t, f.stateDir) {
		found = found || (e.Outcome == "upgrade_rolled_back" && e.ReasonCode == "UPGRADE_ROLLED_BACK")
	}
	if !found {
		t.Fatal("upgrade_rolled_back not recorded")
	}
	if _, err := os.Stat(filepath.Join(f.stateDir, ops.UpgradeEventFile)); err == nil {
		t.Fatal("marker not removed")
	}
}
