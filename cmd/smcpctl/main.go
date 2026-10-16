// Command smcpctl is the administrative CLI (FR-12.7 subset): bootstrap,
// config validate, journal verify, health and hash-password. Emergency stop,
// backup and restore need the admin listener, which is not in this slice.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

const usage = `usage: smcpctl <command> [flags]

  bootstrap        create state, keys, TLS certificates and example config and policy
  config validate  validate the configuration and policy files
  journal verify   verify the evidence journal's hash chain and signatures
  health           query the running Gateway's health endpoint
  hash-password    print an Argon2id hash of a password (for client secrets)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "bootstrap":
		err = bootstrap(os.Args[2:])
	case "config":
		if len(os.Args) > 2 && os.Args[2] == "validate" {
			err = validate(os.Args[3:])
		} else {
			err = fmt.Errorf("usage: smcpctl config validate --config <file>")
		}
	case "journal":
		if len(os.Args) > 2 && os.Args[2] == "verify" {
			err = verify(os.Args[3:])
		} else {
			err = fmt.Errorf("usage: smcpctl journal verify --config <file>")
		}
	case "health":
		err = health(os.Args[2:])
	case "hash-password":
		err = hashPassword(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "smcpctl:", err)
		os.Exit(1)
	}
}

const exampleConfig = `# Secure MCP Gateway configuration (first vertical slice).
# Validated against internal/config/config.schema.json at startup.

[listener]
address = "127.0.0.1:8443"
public_url = "https://127.0.0.1:8443"

[state]
dir = "state"

[admin]
username = "admin"
password_hash = "%s"

[policy]
file = "policy.json"

# Framework instances (FR-2.1). The profile names a framework profile in policy.json.
[[principal]]
id = "claude-code-local"
framework = "claude-code"
display_name = "Claude Code on this machine"
profile = "dev"

# OAuth client registrations bound to a principal (FR-2.18).
# Claude Code identifies itself with a Client ID Metadata Document URL and a
# loopback redirect on a random port.
[[client]]
client_id = "https://claude.ai/api/mcp/oauth/client-metadata"
principal = "claude-code-local"
redirect_uris = ["http://localhost:*/callback", "http://127.0.0.1:*/callback"]

# Backend MCP servers launched over stdio. Tools are read from the live
# server at startup; the public name is <alias>_<tool>.
[[server]]
alias = "fs"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "%s"]
`

const examplePolicy = `{
  "revision": "r1",
  "framework_profiles": {
    "dev": { "templates": ["read-only", "read-write"], "default_template": "read-only" }
  },
  "templates": {
    "read-only": {
      "description": "Read the sandbox directory",
      "rules": [
        { "id": "ro-fs", "server": "fs", "tools": ["read_file", "read_text_file", "list_directory", "search_files", "get_file_info"] }
      ]
    },
    "read-write": {
      "description": "Read and, with approval, write the sandbox directory",
      "rules": [
        { "id": "rw-read", "server": "fs", "tools": ["read_file", "read_text_file", "list_directory", "search_files", "get_file_info"] },
        { "id": "rw-write", "server": "fs", "tools": ["write_file", "edit_file", "create_directory", "move_file"], "approval": true }
      ]
    }
  }
}
`

func bootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory for smcp.toml, policy.json and state/")
	pw := fs.String("admin-password", os.Getenv("SMCP_ADMIN_PASSWORD"), "administrator password (or SMCP_ADMIN_PASSWORD)")
	sandbox := fs.String("sandbox", "", "directory the example filesystem server may read (default <dir>/sandbox)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pw == "" {
		return fmt.Errorf("--admin-password or SMCP_ADMIN_PASSWORD is required")
	}
	if len(*pw) < 12 {
		return fmt.Errorf("administrator password must be at least 12 characters")
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if *sandbox == "" {
		*sandbox = filepath.Join(abs, "sandbox")
	}
	if err := os.MkdirAll(*sandbox, 0o755); err != nil {
		return err
	}
	stateDir := filepath.Join(abs, "state")
	if err := keys.Ensure(stateDir, "127.0.0.1"); err != nil {
		return err
	}
	cfgPath := filepath.Join(abs, "smcp.toml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		hash, err := keys.HashPassword(*pw)
		if err != nil {
			return err
		}
		if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(exampleConfig, hash, *sandbox)), 0o600); err != nil {
			return err
		}
		fmt.Println("wrote", cfgPath)
	} else {
		fmt.Println("kept existing", cfgPath)
	}
	polPath := filepath.Join(abs, "policy.json")
	if _, err := os.Stat(polPath); os.IsNotExist(err) {
		if err := os.WriteFile(polPath, []byte(examplePolicy), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", polPath)
	} else {
		fmt.Println("kept existing", polPath)
	}
	if _, err := config.Load(cfgPath); err != nil {
		return err
	}
	if _, err := policy.Load(polPath); err != nil {
		return err
	}
	fmt.Printf(`
State and keys are under %s.

Next steps:
  1. Start the Gateway:        smcpd --config %s
  2. Trust the local CA:        export NODE_EXTRA_CA_CERTS=%s
  3. Register with Claude Code: claude mcp add --transport http smcp https://127.0.0.1:8443/mcp
     Claude Code opens a browser for OAuth; sign in as %q.
`, stateDir, cfgPath, filepath.Join(stateDir, keys.CACertFile), "admin")
	return nil
}

func validate(args []string) error {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	snap, err := policy.Load(cfg.Policy.File)
	if err != nil {
		return err
	}
	fmt.Printf("configuration OK: %d principals, %d clients, %d servers; policy revision %s\n", len(cfg.Principals), len(cfg.Clients), len(cfg.Servers), snap.Revision)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("journal verify", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	dir := fs.String("dir", "", "journal directory (default <state>/journal)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	pub, err := keys.LoadEvidencePublicKey(cfg.State.Dir)
	if err != nil {
		return err
	}
	if *dir == "" {
		*dir = filepath.Join(cfg.State.Dir, "journal")
	}
	rep, err := audit.Verify(*dir, pub)
	if err != nil {
		return fmt.Errorf("journal verification FAILED: %w", err)
	}
	fmt.Printf("journal OK: %d segments, %d events", rep.Segments, rep.Events)
	if rep.Open != "" {
		fmt.Printf(" (%s is still open)", rep.Open)
	}
	fmt.Println()
	return nil
}

func health(args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(cfg.State.Dir, keys.CACertFile))
	if err != nil {
		return err
	}
	pool.AppendCertsFromPEM(ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	resp, err := client.Get(cfg.Listener.PublicURL + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var pretty map[string]any
	if json.Unmarshal(b, &pretty) == nil {
		out, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	fmt.Println(strings.TrimSpace(string(b)))
	return nil
}

func hashPassword(args []string) error {
	fs := flag.NewFlagSet("hash-password", flag.ContinueOnError)
	pw := fs.String("password", os.Getenv("SMCP_PASSWORD"), "password to hash (or SMCP_PASSWORD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pw == "" {
		return fmt.Errorf("--password or SMCP_PASSWORD is required")
	}
	h, err := keys.HashPassword(*pw)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}
