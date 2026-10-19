package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMain lets the test binary act as smcp-hostile when re-executed.
func TestMain(m *testing.M) {
	if os.Getenv("SMCP_HOSTILE_CMD_TEST") == "1" {
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...) // drop -test.run=NONE
		main()
	}
	os.Exit(m.Run())
}

func run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, append([]string{"-test.run=NONE"}, args...)...)
	cmd.Env = append(os.Environ(), "SMCP_HOSTILE_CMD_TEST=1")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	return string(out), err
}

func TestListAndServe(t *testing.T) {
	out, err := run(t, "", "-list")
	if err != nil || !strings.Contains(out, "HF-01") || !strings.Contains(out, "HF-27") {
		t.Fatalf("list: %v %q", err, out)
	}
	req := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
`
	out, err = run(t, req, "-fixture", "HF-04")
	if err != nil || !strings.Contains(out, `"serverInfo"`) || !strings.Contains(out, `"fetch_page"`) {
		t.Fatalf("serve: %v %q", err, out)
	}
	if _, err := run(t, "", "-fixture", "HF-99"); err == nil {
		t.Fatal("unknown fixture accepted")
	}
}
