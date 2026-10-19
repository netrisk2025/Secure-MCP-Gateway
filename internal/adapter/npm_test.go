package adapter_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
	"github.com/ethan03805/secure-mcp-gateway/internal/gwtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func npmDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "packaging", "npm", "smcp-connect"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func needNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	return node
}

func TestNPMUnit(t *testing.T) {
	node := needNode(t)
	cmd := exec.Command(node, "--test")
	cmd.Dir = filepath.Join(npmDir(t), "test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node --test: %v\n%s", err, out)
	}
}

func TestNPMConnect(t *testing.T) {
	reqtest.Partial(t, "FR-16.9")
	// Partial: the npm package through a tunnel: dynamic registration,
	// operator approval, device sign-in, the shared CP-43 file at mode
	// 0600, relayed initialize and tools/call. Conformance fixtures
	// (FR-12.9) do not exist yet.
	node := needNode(t)
	g := gwtest.Start(t, "[remote]\naddress = \"%REMOTE%\"\ndefault_principal = \"cloud\"\ntemplates = [\"remote\"]\n")
	public := g.Tunnel(func() string { return "203.0.113.11" })
	g.EnableRemote(public)
	credPath := filepath.Join(t.TempDir(), "smcp", "credentials.toml")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, filepath.Join(npmDir(t), "bin", "smcp-connect.js"),
		"--url", public+"/mcp", "--credentials", credPath, "--ca", g.CAFile, "--scope", "smcp:template:remote")
	cmd.Env = append(os.Environ(), "SMCP_CONNECT_POLL_MS=20")
	stdin, _ := cmd.StdinPipe()
	stderr, _ := cmd.StderrPipe()
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(stderr)
	codeRE := regexp.MustCompile(`enter the code ([A-Z]{4}-[A-Z]{4})`)
	pendingRE := regexp.MustCompile(`client (smcp-dcr-\S+) is waiting`)
	var log strings.Builder
	for sc.Scan() {
		line := sc.Text()
		log.WriteString(line + "\n")
		if m := pendingRE.FindStringSubmatch(line); m != nil {
			if st, body := g.Admin("POST", "/api/v1/clients/"+m[1]+"/approve", map[string]any{}); st != 200 {
				t.Fatalf("approve %d %v", st, body)
			}
		}
		if m := codeRE.FindStringSubmatch(line); m != nil {
			form := url.Values{"user_code": {m[1]}, "username": {gwtest.ApproverUser}, "password": {gwtest.ApproverPassword}, "decision": {"approve"}}
			req, _ := http.NewRequest("POST", public+"/oauth/device", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := g.HTTP.Do(req)
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("approve code: %v %v", err, resp)
			}
			resp.Body.Close()
		}
		if strings.Contains(line, "signed in") {
			break
		}
	}
	go func() { _, _ = io.Copy(&log, stderr) }()
	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"npm-test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	for _, m := range msgs {
		_, _ = io.WriteString(stdin, m+"\n")
	}
	time.Sleep(500 * time.Millisecond) // initialize answered before the call uses its version
	_, _ = io.WriteString(stdin, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"from npm"}}}`+"\n")
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("smcp-connect: %v\n%s", err, log.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `"protocolVersion":"2025-11-25"`) || !strings.Contains(out, "echo:from npm") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", out, log.String())
	}
	if fi, err := os.Stat(credPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file %v %v", fi, err)
	}
	// The Go adapters read the file the npm package wrote.
	c, err := adapter.Load(credPath)
	if err != nil || c.Session.RefreshToken == "" || c.Session.IssuedAt.IsZero() {
		t.Fatalf("Go read of the npm credential file: %+v %v", c, err)
	}
	g.WaitEvent(func(e auditEvent) bool {
		return e.Channel == "remote" && e.ClientAddress == "203.0.113.11" && e.Class == "call"
	})
}
