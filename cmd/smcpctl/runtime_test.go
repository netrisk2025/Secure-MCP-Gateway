package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestRuntimeCommands(t *testing.T) {
	reqtest.Partial(t, "FR-5.9")
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	share := filepath.Join(dir, "sandbox")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("\n[runtime]\nsandbox = \"podman\"\n[[runtime.server]]\nalias = \"ref\"\n[[runtime.server.mount]]\nsource = \"" + share + "\"\ntarget = \"/data\"\n")
	f.Close()

	// spec works offline on any platform and prints names, not values.
	out := mustCtl(t, "runtime", "spec", "--config", cfgPath)
	var doc struct {
		Sandbox string `json:"sandbox"`
		Servers []struct {
			LaunchSpec struct {
				Alias    string `json:"alias"`
				Artifact struct {
					Digest string `json:"digest"`
				} `json:"artifact"`
			} `json:"launch_spec"`
			PodmanArgs []string `json:"podman_args"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if doc.Sandbox != "podman" || len(doc.Servers) != 1 || doc.Servers[0].LaunchSpec.Alias != "ref" ||
		!strings.HasPrefix(doc.Servers[0].LaunchSpec.Artifact.Digest, "sha256:") {
		t.Fatalf("%s", out)
	}
	args := doc.Servers[0].PodmanArgs
	for _, want := range []string{"--read-only", "--cap-drop=all", "--network=none", "--mount=type=bind,src=" + share + ",dst=/data,ro,bind-propagation=rprivate"} {
		if !slices.Contains(args, want) {
			t.Errorf("spec lacks %s", want)
		}
	}

	out, err = ctl(t, "", "runtime", "doctor")
	if runtime.GOOS != "linux" && (err == nil || !strings.Contains(out, "FAIL  Linux")) {
		t.Fatalf("doctor on %s: %v %s", runtime.GOOS, err, out)
	}
	out, _ = ctl(t, "", "runtime", "doctor", "--json")
	if !strings.Contains(out, `"checks"`) {
		t.Fatalf("doctor --json: %s", out)
	}
	if out, err := ctl(t, "", "runtime", "show"); err == nil || !strings.Contains(out, "instance ID is required") {
		t.Fatalf("show without id: %v %s", err, out)
	}
	if out, err := ctl(t, "", "runtime", "bogus"); err == nil || !strings.Contains(out, "usage: smcpctl runtime") {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := ctl(t, "", "runtime", "help"); err != nil || !strings.Contains(out, "kill <id>") {
		t.Fatalf("%v %s", err, out)
	}
	if out := mustCtl(t, "help"); !strings.Contains(out, "runtime") {
		t.Fatal(out)
	}
}

// TestRuntimeSpecEgressAndSlotMounts: smcpctl runtime spec shows the
// Egress Broker variables an egress instance receives (FR-5.37: proxy
// variables and the endpoint base-URL variable of its grant, with a
// placeholder port), and mounts only the part of a packaged server's mount
// grant that its manifest declares as a filesystem slot (SR-4.6-1): a
// grant of the slot's parent directory mounts the slot alone, read-only
// (the reference manifest declares it "ro") although the grant asks for
// write, and a grant outside every slot is refused.
func TestRuntimeSpecEgressAndSlotMounts(t *testing.T) {
	reqtest.Partial(t, "FR-5.37", "SR-4.6-1")
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	share := filepath.Join(dir, "sandbox")
	base, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	write := func(extra string) {
		t.Helper()
		if err := os.WriteFile(cfgPath, append(append([]byte{}, base...), extra...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`
[egress]
enabled = true

[[egress.grant]]
server = "web"
host = "api.example.com"
ports = [443]
methods = ["GET"]
endpoint_env = "WEB_API_URL"

[runtime]
sandbox = "podman"

[[server]]
alias = "web"
command = "` + filepath.Join(binDir, "smcp-refserver") + `"

[[runtime.server]]
alias = "web"
network = "egress"

[[runtime.server]]
alias = "ref"
[[runtime.server.mount]]
source = "` + dir + `"
target = "/data"
write = true
`)
	out := mustCtl(t, "runtime", "spec", "--config", cfgPath)
	var doc struct {
		Servers []struct {
			LaunchSpec struct {
				Alias     string            `json:"alias"`
				EgressEnv map[string]string `json:"egress_env"`
				Mounts    []struct {
					Source string `json:"source"`
					Target string `json:"target"`
					Write  bool   `json:"write"`
				} `json:"mounts"`
			} `json:"launch_spec"`
			PodmanArgs []string `json:"podman_args"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	seen := map[string]bool{}
	for _, s := range doc.Servers {
		ls := s.LaunchSpec
		seen[ls.Alias] = true
		switch ls.Alias {
		case "web":
			for _, k := range []string{"WEB_API_URL", "HTTP_PROXY", "HTTPS_PROXY"} {
				if !strings.HasPrefix(ls.EgressEnv[k], "http://10.0.2.2:") {
					t.Errorf("egress_env %s = %q", k, ls.EgressEnv[k])
				}
			}
			if !slices.Contains(s.PodmanArgs, "--env=WEB_API_URL="+ls.EgressEnv["WEB_API_URL"]) {
				t.Errorf("podman args lack the endpoint variable: %v", s.PodmanArgs)
			}
		case "ref":
			if len(ls.EgressEnv) != 0 {
				t.Errorf("ref has egress variables: %v", ls.EgressEnv)
			}
			var data []string
			for _, m := range ls.Mounts {
				if strings.HasPrefix(m.Target, "/data") {
					data = append(data, m.Source+" -> "+m.Target+" write="+strconv.FormatBool(m.Write))
				}
			}
			if want := share + " -> /data/sandbox write=false"; len(data) != 1 || data[0] != want {
				t.Errorf("ref grant mounts %v, want only %s", data, want)
			}
		}
	}
	if !seen["web"] || !seen["ref"] {
		t.Fatalf("%s", out)
	}

	outside := t.TempDir()
	write(`
[runtime]
sandbox = "podman"

[[runtime.server]]
alias = "ref"
[[runtime.server.mount]]
source = "` + outside + `"
`)
	if out, err := ctl(t, "", "runtime", "spec", "--config", cfgPath); err == nil || !strings.Contains(out, "outside every filesystem slot") {
		t.Fatalf("a grant outside the slots: %v\n%s", err, out)
	}
}

func TestRuntimeControlCommandsStandalone(t *testing.T) {
	dir := t.TempDir()
	secrets := t.TempDir()
	adminPW := writeFile(t, secrets, "admin", "admin password 12\n")
	approverPW := writeFile(t, secrets, "approver", "approver password 1\n")
	mustCtl(t, "bootstrap", "--dir", dir, "--admin-password-file", adminPW, "--approver-password-file", approverPW,
		"--refserver", filepath.Join(binDir, "smcp-refserver"), "--port", freePort(t), "--admin-port", freePort(t), "--metrics-port", freePort(t), "--notify", "off")
	cfgPath := filepath.Join(dir, "smcp.toml")
	d := startDaemon(t, cfgPath)
	defer stopDaemon(t, d)
	if out := mustCtl(t, "runtime", "status", "--config", cfgPath); !strings.Contains(out, `"sandbox": "none"`) {
		t.Fatalf("status: %s", out)
	}
	if out := mustCtl(t, "runtime", "instances", "--config", cfgPath); !strings.Contains(out, `"instances": []`) {
		t.Fatalf("instances: %s", out)
	}
	if out, err := ctl(t, "", "runtime", "kill", "0192", "--config", cfgPath, "--reason", "x"); err == nil || !strings.Contains(out, "no_instance") {
		t.Fatalf("kill: %v %s", err, out)
	}
}
