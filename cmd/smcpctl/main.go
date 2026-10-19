// Command smcpctl is the administrative CLI (FR-12.7 subset). Offline
// commands work on the configuration and state directory; control commands
// talk to the running Gateway's control API on the admin listener with the
// local operator token from the state directory.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

const usage = `usage: smcpctl <command> [flags]

Offline:
  bootstrap        create state, keys, TLS certificates, example config and policy
  config validate  validate the configuration and policy files
  journal verify   verify the evidence journal (hash chain, signatures, key transitions, anchor)
  journal export   copy closed journal segments and the anchor to an export directory
  config migrate   rewrite the configuration to this release's schema_version
  hash-password    print an Argon2id hash of a password (prompt or --password-file)
  uds key          generate a UDS bearer key into a 0600 file and print its key_hash
  package          build, sign, verify, install and manage server packages (smcpctl package help)
  trust            enroll, list and remove package signing keys (trust anchors)
  filters          list, export and test the inspection rule sets (rules, export, scan)
  restore          restore an encrypted backup (the Gateway must be stopped)
  install          install as a service: --profile standalone (launchd or systemd
                   user unit) or enforced (Linux, root); idempotent
  upgrade          install a new release with backup, health check and rollback
  uninstall        remove services and binaries, keep evidence (--purge removes all)
  version          print the version (and the running Gateway's label)

Control API (running Gateway; backup and keys also work offline):
  health           show the health monitor's report; health ack <cause>
  reload           reload the configuration file (also SIGHUP)
  keys             keys status | keys rotate tls|ca|evidence
  backup           write an encrypted backup (passphrase or age recipient)
  stop             emergency stop: refuse every tool call until resumed
  resume           leave emergency stop
  policy reload    publish the configured policy file through the Policy Store
  policy ...       validate, diff, simulate, publish, rollback, history, show
                   (smcpctl policy help)
  approvals        list, show, approve, deny or watch tool-call approvals
  approvers        list, add or remove Session Approver accounts (FR-2.23)
  graph            graph mirror status, rebuild, canned queries, engine config
  observe          observation status, anomalies, baselines, campaigns, exports
  admin redeem     set the administrator password with the one-use bootstrap token
  egress           Egress Broker status, grants and recent connections (smcpctl egress -h)
  servers          Local Server Registry: list, show <alias>, suspended-tools
  runtime          sandboxed server instances and enforced-profile checks (smcpctl runtime help)
  secrets          secret vault: init (offline), list, show, set, rotate, rm, impact, resume, reload
  remote           Remote Access Profile: enable, disable, status, check (tunnels)
  clients          remote client registrations; harness setup (clients setup <client>)
  lockdown         apply, show or remove a client lockdown profile
  doctor           report non-Gateway MCP servers, readable Gateway paths, CA trust

Every command takes --config <file> (default smcp.toml).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	sub := func(name string) bool { return len(args) > 1 && args[1] == name }
	var err error
	switch {
	case args[0] == "bootstrap":
		err = bootstrap(args[1:], stdout)
	case args[0] == "config" && sub("validate"):
		err = validate(args[2:], stdout)
	case args[0] == "journal" && sub("verify"):
		err = verifyJournal(args[2:], stdout)
	case args[0] == "package":
		err = packageCmd(args[1:], stdout)
	case args[0] == "trust":
		err = trustCmd(args[1:], stdout)
	case args[0] == "hash-password":
		err = hashPassword(args[1:], stdout)
	case args[0] == "uds":
		err = udsCmd(args[1:], stdout)
	case args[0] == "filters":
		err = filtersCmd(args[1:], os.Stdin, stdout)
	case args[0] == "health":
		err = healthCmd(args[1:], stdout)
	case args[0] == "reload":
		err = reloadCmd(args[1:], stdout)
	case args[0] == "keys":
		err = keysCmd(args[1:], stdout)
	case args[0] == "backup":
		err = backupCmd(args[1:], stdout)
	case args[0] == "restore":
		err = restoreCmd(args[1:], stdout)
	case args[0] == "journal" && sub("export"):
		err = journalExport(args[2:], stdout)
	case args[0] == "config" && sub("migrate"):
		err = configMigrate(args[2:], stdout)
	case args[0] == "version":
		err = versionCmd(args[1:], stdout)
	case args[0] == "upgrade":
		err = upgradeCmd(args[1:], stdout)
	case args[0] == "install":
		err = installCmd(args[1:], stdout)
	case args[0] == "uninstall":
		err = uninstallCmd(args[1:], os.Stdin, stdout)
	case args[0] == "stop":
		err = stopCmd(args[1:], stdout)
	case args[0] == "resume":
		err = control(args[1:], stdout, "POST", "/admin/v1/resume", map[string]any{})
	case args[0] == "policy" && sub("reload"):
		err = control(args[2:], stdout, "POST", "/admin/v1/policy/reload", map[string]any{})
	case args[0] == "policy":
		err = policyCmd(args[1:], stdout)
	case args[0] == "approvers":
		err = approversCmd(args[1:], stdout)
	case args[0] == "approvals":
		err = approvalsCmd(args[1:], os.Stdin, stdout)
	case args[0] == "graph":
		err = graphCmd(args[1:], os.Stdin, stdout)
	case args[0] == "observe":
		err = observeCmd(args[1:], stdout)
	case args[0] == "admin" && sub("redeem"):
		err = redeem(args[2:], stdout)
	case args[0] == "remote":
		err = remoteCmd(args[1:], stdout)
	case args[0] == "clients" || args[0] == "client":
		err = clientsCmd(args[1:], stdout)
	case args[0] == "lockdown":
		err = lockdownCmd(args[1:], stdout)
	case args[0] == "doctor":
		err = doctorCmd(args[1:], stdout)
	case args[0] == "egress":
		err = egressCmd(args[1:], stdout)
	case args[0] == "runtime":
		err = runtimeCmd(args[1:], stdout)
	case args[0] == "secrets":
		err = secretsCmd(args[1:], stdout)
	case args[0] == "servers":
		err = serversCmd(args[1:], stdout)
	case args[0] == "help" || args[0] == "-h" || args[0] == "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "smcpctl:", err)
		return 1
	}
	return 0
}

func validate(args []string, out io.Writer) error {
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
	fmt.Fprintf(out, "configuration OK: %d principals, %d clients, %d servers, %d approvers; policy revision %s\n",
		len(cfg.Principals), len(cfg.Clients), len(cfg.Servers), len(cfg.Approvers), snap.Revision)
	return nil
}

// readSecret reads a secret from file ("-" is standard input) or, when file
// is empty, from an interactive prompt with confirmation. Secrets are never
// taken from the command line or the environment, and a file readable or
// writable by group or others is refused (SR-7.5-2).
func readSecret(file, prompt string, confirm bool) (string, error) {
	if file != "" {
		var b []byte
		var err error
		if file == "-" {
			b, err = io.ReadAll(io.LimitReader(os.Stdin, 4096))
		} else {
			b, err = readPrivateFile(file)
		}
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no terminal for the password prompt; pass a password file")
	}
	fmt.Fprint(os.Stderr, prompt+": ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", errors.New("the two entries differ")
		}
	}
	return string(a), nil
}

// readPrivateFile reads a secret file whose mode is 0600 or stricter.
func readPrivateFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %04o; a secret file must be mode 0600 or stricter (chmod 600 %s)", path, perm, path)
	}
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

// errPasswordArg refuses a password given as a command-line argument.
var errPasswordArg = errors.New("passwords are never accepted as command-line arguments; use the prompt or a password file with mode 0600")

// readPassword reads a password or bootstrap secret for bootstrap,
// hash-password and admin redeem: only from the interactive prompt or a
// file with mode 0600 or stricter (SR-7.5-2), never from standard input.
func readPassword(file, prompt string, confirm bool) (string, error) {
	if file == "-" {
		return "", errors.New("standard input is not accepted for this password; use the prompt or a password file with mode 0600")
	}
	return readSecret(file, prompt, confirm)
}

func hashPassword(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("hash-password", flag.ContinueOnError)
	file := fs.String("password-file", "", "read the password from this file (mode 0600 or stricter) instead of a prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errPasswordArg
	}
	pw, err := readPassword(*file, "Password", true)
	if err != nil {
		return err
	}
	if pw == "" {
		return errors.New("empty password")
	}
	h, err := keys.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, h)
	return nil
}
