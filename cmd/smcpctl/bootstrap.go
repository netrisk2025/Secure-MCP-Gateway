package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// bootstrapTokenLifetime bounds how long a one-use bootstrap token can be
// redeemed.
const bootstrapTokenLifetime = 24 * time.Hour

const exampleConfig = `# Secure MCP Gateway configuration.
# Validated against internal/config/config.schema.json at startup.

# Configuration format version (FR-13.13); smcpctl config migrate updates it.
schema_version = 1

[listener]
address = %[1]q
public_url = %[2]q

[admin_listener]
address = %[3]q

[state]
dir = %[12]q

# Administrator of the control API (smcpctl stop/resume/policy reload use
# the operator token in state/keys/admin.token instead).
[admin]
username = "admin"
%[4]s

# Session Approvers approve harness sign-ins in the browser (FR-2.19). The
# administrator account cannot. Add more with smcpctl hash-password.
[[approver]]
username = "approver"
password_hash = %[5]q

[policy]
file = %[13]q

# Framework instances (FR-2.1). The profile names a framework profile in policy.json.
[[principal]]
id = "claude-code-local"
framework = "claude-code"
display_name = "Claude Code on this machine"
profile = "dev"

# OAuth client registrations bound to a principal (FR-2.18). Claude Code
# identifies itself with this client ID and a loopback redirect on a random
# port.
[[client]]
client_id = "https://claude.ai/api/mcp/oauth/client-metadata"
principal = "claude-code-local"
redirect_uris = ["http://localhost:*/callback", "http://127.0.0.1:*/callback"]

# Backend MCP servers. Each is a signed package (smcpctl package list): the
# enabled revision of the named server ID is launched from the
# content-addressed store under state/packages, after its artifact digest is
# checked against package_sha256 and the signed manifest. Package runners
# such as npx or uvx are refused (SR-3.6-1). The reference server below ships
# with the Gateway, was packaged by bootstrap and offers read-only tools on
# the directory bound to its "root" slot.
[[server]]
alias = "ref"
package = %[6]q
package_sha256 = %[7]q
slots = { root = %[8]q }

# Elements enabled by this file. Every element below runs without other
# software; smcpctl health lists the elements and their state
# (info.elements).
#
# Always on, with no table needed: request and response inspection
# (E-09/E-11, [filters]), the signed Policy Store (E-05), the package
# library (E-13/E-14, [packages]), the Evidence Journal (E-21), the health
# monitor (E-23), the management console at the admin URL (E-24) and
# observation with anomaly scoring (SS-10, [observation]; the store is
# DuckDB when the build has it, JSON Lines otherwise).

# Approval Service (E-07). notify: auto, off, osascript, terminal-notifier,
# notify-send or command (with notify_command).
[approvals]
notify = %[9]q

# Prometheus metrics on loopback (E-23).
[metrics]
enabled = %[10]t
address = %[11]q

# Elements that need setup first, off by default:
#
# Encrypted evidence export (E-21) to storage off this machine:
#   [evidence]
#   export_dir = "/Volumes/backup/smcp-evidence"
#
# Egress Broker (E-18): servers reach the network only through per-instance
# proxies with per-server grants. Advisory in the standalone profile. A
# grant must stay within the egress capabilities of the server's signed
# manifest (the reference server declares none), and each operation needs
# a one-use capability that the Gateway delivers with the call
# (docs/egress.md).
#   [egress]
#   enabled = true
#   [[egress.grant]]
#   server = "web"
#   host = "api.example.com"
#   methods = ["GET"]
#
# Secret Vault and Secret Broker (E-19/E-20): run "smcpctl secrets init",
# write a Secret Use Policy, then add
#   [secrets]
#   use_policy_file = "secret-use.json"
#
# Enforced profile (E-15/E-16/E-17, Linux with rootless Podman): see
# "smcpctl runtime doctor", then
#   [profile]
#   mode = "enforced"
#   [runtime]
#   sandbox = "podman"
#
# Graph mirror (SS-9, optional, needs a local Neo4j; never blocks calls):
#   [graph]
#   enabled = true
#   uri = "bolt://127.0.0.1:7687"
#   password_file = "neo4j.password"
#
# Remote Access Profile (E-33): "smcpctl remote enable" with a tunnel.
%[14]s`

const examplePolicy = `{
  "revision": "r1",
  "framework_profiles": {
    "dev": { "templates": ["read-only", "approval-demo"], "default_template": "read-only" }
  },
  "templates": {
    "read-only": {
      "description": "Read the sandbox directory with the reference server",
      "rules": [
        { "id": "ro-ref", "server": "ref", "tools": ["echo", "time_now", "list_files", "read_file"] }
      ]
    },
    "approval-demo": {
      "description": "As read-only, but reading a file needs a person's approval",
      "rules": [
        { "id": "demo-free", "server": "ref", "tools": ["echo", "time_now", "list_files"] },
        { "id": "demo-approve", "server": "ref", "tools": ["read_file"], "approval": true }
      ]
    }
  }
}
`

// findRefserver locates the reference server: next to this executable, then
// on PATH. The result is absolute, because PATH lookup at launch time is
// refused.
func findRefserver() (string, error) {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "smcp-refserver")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	p, err := exec.LookPath("smcp-refserver")
	if err != nil {
		return "", errors.New("smcp-refserver not found next to smcpctl or on PATH; build it (go build ./cmd/smcp-refserver) or pass --refserver")
	}
	return filepath.Abs(p)
}

// bootstrapOpts are the inputs of runBootstrap. bootstrap fills them from
// flags; install (install.go) fills them for a CP-46 layout.
type bootstrapOpts struct {
	dir                     string // absolute: smcp.toml and policy.json
	stateDir                string // absolute; empty means <dir>/state, written as "state"
	policyFile              string // value of [policy] file; empty means "policy.json"
	extraConfig             string // TOML appended to a new smcp.toml
	adminFile, approverFile string
	useToken                bool
	sandbox, refserver      string
	port, adminPort         int
	metricsPort             int
	notify                  string
	quiet                   bool // no "Next steps" text (install prints its own)
}

// bootstrapResult reports what runBootstrap created.
type bootstrapResult struct {
	cfgPath, polPath, stateDir string
	cfgCreated, polCreated     bool
	keysCreated                bool
}

func bootstrap(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory for smcp.toml, policy.json and state/")
	o := bootstrapOpts{}
	fs.StringVar(&o.adminFile, "admin-password-file", "", "read the administrator password from this file (mode 0600 or stricter) instead of a prompt")
	fs.StringVar(&o.approverFile, "approver-password-file", "", "read the Session Approver password from this file (mode 0600 or stricter) instead of a prompt")
	fs.BoolVar(&o.useToken, "bootstrap-token", false, "set no administrator password now; print a one-use token to set it later with `smcpctl admin redeem`")
	fs.StringVar(&o.sandbox, "sandbox", "", "directory the reference server may read (default <dir>/sandbox)")
	fs.StringVar(&o.refserver, "refserver", "", "path of smcp-refserver (default: next to smcpctl, then PATH)")
	fs.IntVar(&o.port, "port", 8443, "harness listener port on 127.0.0.1")
	fs.IntVar(&o.adminPort, "admin-port", 8444, "control API listener port on 127.0.0.1")
	fs.IntVar(&o.metricsPort, "metrics-port", -1, "metrics endpoint port on 127.0.0.1 (default admin port + 1; 0 turns metrics off)")
	fs.StringVar(&o.notify, "notify", "auto", "approval desktop notifications: auto, off, osascript, terminal-notifier or notify-send")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errPasswordArg
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	o.dir = abs
	_, err = runBootstrap(o, out)
	return err
}

// keyFiles are the files keys.Ensure creates when they are missing.
var keyFiles = []string{keys.CAKeyFile, keys.ServerKeyFile, keys.EvidenceKeyFile, keys.AdminTokenFile, keys.InstallationIDFile}

func runBootstrap(o bootstrapOpts, out io.Writer) (bootstrapResult, error) {
	var r bootstrapResult
	abs := o.dir
	cfgPath := filepath.Join(abs, "smcp.toml")
	r.cfgPath = cfgPath
	_, statErr := os.Stat(cfgPath)
	writeCfg := os.IsNotExist(statErr)

	var adminLine, token string
	var approverHash string
	var err error
	if writeCfg {
		if o.useToken {
			token = ids.Secret()
			sum := sha256.Sum256([]byte(token))
			adminLine = fmt.Sprintf("bootstrap_token_sha256 = %q\nbootstrap_token_expires = %q", hex.EncodeToString(sum[:]),
				time.Now().Add(bootstrapTokenLifetime).UTC().Format(time.RFC3339))
		} else {
			pw, err := readPassword(o.adminFile, "Administrator password (12 or more characters)", true)
			if err != nil {
				return r, fmt.Errorf("administrator password: %w (or use --bootstrap-token)", err)
			}
			if len(pw) < 12 {
				return r, errors.New("administrator password must be at least 12 characters")
			}
			h, err := keys.HashPassword(pw)
			if err != nil {
				return r, err
			}
			adminLine = fmt.Sprintf("password_hash = %q", h)
		}
		apw, err := readPassword(o.approverFile, "Session Approver password (approves harness sign-ins; 12 or more characters)", true)
		if err != nil {
			return r, fmt.Errorf("approver password: %w", err)
		}
		if len(apw) < 12 {
			return r, errors.New("approver password must be at least 12 characters")
		}
		if approverHash, err = keys.HashPassword(apw); err != nil {
			return r, err
		}
		if o.refserver == "" {
			if o.refserver, err = findRefserver(); err != nil {
				return r, err
			}
		}
		if o.refserver, err = filepath.Abs(o.refserver); err != nil {
			return r, err
		}
	}
	if o.sandbox == "" {
		o.sandbox = filepath.Join(abs, "sandbox")
	}
	if err := os.MkdirAll(o.sandbox, 0o755); err != nil {
		return r, err
	}
	stateDir, stateValue := filepath.Join(abs, "state"), "state"
	if o.stateDir != "" {
		stateDir, stateValue = o.stateDir, o.stateDir
	}
	r.stateDir = stateDir
	for _, f := range keyFiles {
		if _, err := os.Stat(filepath.Join(stateDir, f)); err != nil {
			r.keysCreated = true
		}
	}
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		return r, err
	}
	policyValue := o.policyFile
	if policyValue == "" {
		policyValue = "policy.json"
	}
	listen := fmt.Sprintf("127.0.0.1:%d", o.port)
	if writeCfg {
		refSHA, err := bootstrapRefPackage(stateDir, o.refserver, out)
		if err != nil {
			return r, err
		}
		mport := o.metricsPort
		if mport < 0 {
			mport = o.adminPort + 1
		}
		maddr := fmt.Sprintf("127.0.0.1:%d", mport)
		if mport == 0 {
			maddr = config.DefaultMetricsAddress
		}
		body := fmt.Sprintf(exampleConfig, listen, "https://"+listen, fmt.Sprintf("127.0.0.1:%d", o.adminPort), adminLine, approverHash, RefPackageID, refSHA, o.sandbox,
			o.notify, mport != 0, maddr, stateValue, policyValue, o.extraConfig)
		if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
			return r, err
		}
		r.cfgCreated = true
		if !o.quiet {
			fmt.Fprintln(out, "wrote", cfgPath)
		}
	} else {
		if !o.quiet {
			fmt.Fprintln(out, "kept existing", cfgPath)
		}
	}
	polPath := policyValue
	if !filepath.IsAbs(polPath) {
		polPath = filepath.Join(abs, polPath)
	}
	r.polPath = polPath
	if _, err := os.Stat(polPath); os.IsNotExist(err) {
		if err := os.WriteFile(polPath, []byte(examplePolicy), 0o644); err != nil {
			return r, err
		}
		r.polCreated = true
		if !o.quiet {
			fmt.Fprintln(out, "wrote", polPath)
		}
	} else {
		if !o.quiet {
			fmt.Fprintln(out, "kept existing", polPath)
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return r, err
	}
	if _, err := policy.Load(polPath); err != nil {
		return r, err
	}
	if token != "" {
		fmt.Fprintf(out, `
One-use bootstrap token (shown once, valid for 24 hours):

  %s

After starting smcpd, set the administrator password with:
  smcpctl admin redeem --config %s
`, token, cfgPath)
	}
	if o.quiet {
		return r, nil
	}
	fmt.Fprintf(out, `
State and keys are under %s.

Next steps:
  1. Start the Gateway:        smcpd --config %s
  2. Trust the local CA:        export NODE_EXTRA_CA_CERTS=%s
  3. Register with Claude Code: claude mcp add --transport http smcp %s
     Claude Code opens a browser for OAuth; sign in as the Session Approver "approver".
  4. Check health:              smcpctl health --config %s
`, stateDir, cfgPath, filepath.Join(stateDir, keys.CACertFile), cfg.ResourceURI(), cfgPath)
	return r, nil
}
