package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

const secretsUsage = `usage: smcpctl secrets <command> [flags]

  init            create the vault and its master key (offline)
  list            list secrets (metadata only), the vault status and the use policy
  show NAME       show one secret's metadata and versions
  set NAME        create a secret; the value is read from --value-file, standard input or a prompt
  rotate NAME     store a new version; the previous one stays deliverable for --overlap
  rm NAME         retire every version and delete the secret
  impact NAME     list the use policies, servers and slots that reference the secret
  resume NAME     lift a leak suspension after review
  reload          validate and activate the Secret Use Policy file

Secret values are never accepted as command-line arguments.
Every command takes --config <file> (default smcp.toml).
`

// secretsStdin is where values are read from when not prompting (tests
// replace it).
var secretsStdin io.Reader = os.Stdin

// stdinIsTerminal reports whether values should be prompted for.
var stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

var errValueArg = errors.New("secret values are never accepted on the command line; use --value-file, standard input or the prompt")

func secretsCmd(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, secretsUsage)
		return nil
	}
	for _, a := range args {
		if a == "--value" || a == "-value" || strings.HasPrefix(a, "--value=") || strings.HasPrefix(a, "-value=") {
			return errValueArg
		}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "init":
		return secretsInit(rest, out)
	case "list":
		return control(rest, out, "GET", "/api/v1/secrets", nil)
	case "reload":
		return control(rest, out, "POST", "/api/v1/secrets/reload", map[string]any{})
	case "show", "rm", "impact", "resume", "set", "rotate":
	default:
		return fmt.Errorf("unknown secrets command %q\n%s", sub, secretsUsage)
	}
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		return fmt.Errorf("secrets %s needs a secret NAME first", sub)
	}
	name, rest := rest[0], rest[1:]
	path := "/api/v1/secrets/" + url.PathEscape(name)
	switch sub {
	case "show":
		return control(rest, out, "GET", path, nil)
	case "rm":
		return control(rest, out, "DELETE", path, nil)
	case "impact":
		return control(rest, out, "GET", path+"/impact", nil)
	case "resume":
		return control(rest, out, "POST", path+"/resume", map[string]any{})
	case "set":
		return secretsSet(name, rest, out)
	default:
		return secretsRotate(name, path, rest, out)
	}
}

// readValue reads a secret value: from file ("-" is standard input), from
// standard input when it is not a terminal, or from a prompt with
// confirmation. One trailing newline is removed.
func readValue(file string) ([]byte, error) {
	var b []byte
	var err error
	switch {
	case file == "-" || (file == "" && !stdinIsTerminal()):
		b, err = io.ReadAll(io.LimitReader(secretsStdin, secrets.MaxValueBytes+2))
	case file != "":
		b, err = readOwnerOnly(file)
	default:
		s, perr := readSecret("", "Secret value", true)
		b, err = []byte(s), perr
	}
	if err != nil {
		return nil, err
	}
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	if len(b) == 0 {
		return nil, errors.New("empty secret value")
	}
	return b, nil
}

func readOwnerOnly(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %o; a value file must be 0600 or stricter", path, st.Mode().Perm())
	}
	return os.ReadFile(path)
}

func secretsSet(name string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("secrets set", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	typ := fs.String("type", "generic", "secret type: "+strings.Join(secrets.Types, ", "))
	owner := fs.String("owner", "", "owner (default the authenticated actor)")
	desc := fs.String("description", "", "description")
	expires := fs.String("expires", "", "expiry, RFC 3339")
	file := fs.String("value-file", "", "read the value from this file (mode 0600; - for standard input)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := readValue(*file)
	if err != nil {
		return err
	}
	body := map[string]any{"name": name, "type": *typ, "owner": *owner, "description": *desc, "expires": *expires, "value": string(v)}
	clear(v)
	return control([]string{"--config", *cfgPath}, out, "POST", "/api/v1/secrets", body)
}

func secretsRotate(name, path string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("secrets rotate", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	overlap := fs.String("overlap", "", "how long the previous version stays deliverable (0s to 24h; default [secrets] rotation_overlap)")
	file := fs.String("value-file", "", "read the value from this file (mode 0600; - for standard input)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	v, err := readValue(*file)
	if err != nil {
		return err
	}
	body := map[string]any{"value": string(v), "overlap": *overlap}
	clear(v)
	return control([]string{"--config", *cfgPath}, out, "POST", path+"/rotate", body)
}

func secretsInit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("secrets init", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	source := fs.String("key-source", "", "auto, keychain or passphrase (default [secrets] key_source)")
	ppFile := fs.String("passphrase-file", "", "read the vault passphrase from this file (mode 0600) instead of a prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	st, ok := secrets.SettingsFrom(cfg)
	if !ok {
		return errors.New("the configuration has no [secrets] table")
	}
	if *source == "" {
		*source = st.KeySource
	}
	name, err := secrets.ResolveKeySource(*source)
	if err != nil {
		return err
	}
	var ks secrets.KeySource
	switch name {
	case secrets.KeySourceKeychain:
		ks = secrets.Keychain{}
	default:
		pf := *ppFile
		if pf == "" {
			pf = st.PassphraseFile
		}
		pass := func() (string, error) { return readSecret("", "Vault passphrase (12 or more characters)", true) }
		if pf != "" {
			pass = secrets.PassphraseFromFile(pf)
		}
		ks, err = secrets.KeySourceFor(st.VaultDir, secrets.KeySourcePassphrase, pass)
		if err != nil {
			return err
		}
	}
	id, err := secrets.Init(st.VaultDir, ks)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "vault %s initialized in %s (key source %s)\n", id, st.VaultDir, name)
	if name == secrets.KeySourcePassphrase && st.PassphraseFile == "" {
		fmt.Fprintln(out, "set [secrets] passphrase_file to a mode 0600 file holding the passphrase so that smcpd can unlock the vault")
	}
	return nil
}
