package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"aead.dev/minisign"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/profile"
	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox"
)

const packageUsage = `usage: smcpctl package <command> [flags]

  keygen   --out <prefix>                 create a minisign key pair (<prefix>.key, <prefix>.pub)
  build    --recipe <file> --out <dir>    fetch the pinned artifact, probe it, write an unsigned package
  sign     <dir> --key <file>             sign the package index
  verify   <dir> [--pubkey <file>]        verify offline against a key or the enrolled trust anchors
  install  <dir> [--enable] [--alias a]   verify, copy into the library and import
  list                                    list imported revisions and their states
  enable   <id>@<rev> [--alias a]         enable a revision (Administrator)
  disable  <id>@<rev>                     return a revision to verified-disabled
  retire   <id>@<rev>                     retire a revision
  revoke   <id>@<rev> --key <file>        write a signed revocation entry into the library
  scan                                    scan the library now (running Gateway)

Secret keys and passphrases are read from files or a prompt, never from
the command line. Commands that change the registry use the control API
when smcpd is running and the state directory otherwise (--offline forces
the latter).
`

const trustUsage = `usage: smcpctl trust <command> [flags]

  add     <pubkey-file> --name <n> --key-id <ID> [--classes low,moderate] [--expires 2027-10-16|365d]
  list
  remove  <name-or-key-id>
`

// parseArgs parses flags that may follow positional arguments.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// refuseInlineSecrets defines flags that exist only to refuse a secret on
// the command line (FR-14.6).
func refuseInlineSecrets(fs *flag.FlagSet) func() error {
	var key, pass string
	fs.StringVar(&key, "secret-key", "", "refused: pass --key <file>")
	fs.StringVar(&pass, "passphrase", "", "refused: pass --passphrase-file <file> or use the prompt")
	return func() error {
		if key != "" || pass != "" {
			return packaging.Errf(packaging.ReasonKeyOnCommandLine, "secret keys and passphrases are never accepted as command-line arguments; use --key <file> and --passphrase-file or the prompt")
		}
		return nil
	}
}

func packageCmd(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(packageUsage))
	}
	rest := args[1:]
	switch args[0] {
	case "keygen":
		return pkgKeygen(rest, out)
	case "build":
		return pkgBuild(rest, out)
	case "sign":
		return pkgSign(rest, out)
	case "verify":
		return pkgVerify(rest, out)
	case "install":
		return pkgInstall(rest, out)
	case "list":
		return pkgList(rest, out)
	case "enable", "disable", "retire":
		return pkgState(args[0], rest, out)
	case "revoke":
		return pkgRevoke(rest, out)
	case "scan":
		return control(rest, out, "POST", "/api/v1/packages/scan", map[string]any{})
	case "help", "-h", "--help":
		fmt.Fprint(out, packageUsage)
		return nil
	}
	return errors.New(strings.TrimSpace(packageUsage))
}

func pkgKeygen(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("package keygen", flag.ContinueOnError)
	prefix := fs.String("out", "", "path prefix: writes <prefix>.key (mode 0600) and <prefix>.pub")
	passFile := fs.String("passphrase-file", "", "read the passphrase protecting the secret key from this file")
	unencrypted := fs.Bool("unencrypted", false, "write the secret key without a passphrase (protect it by file mode)")
	check := refuseInlineSecrets(fs)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if *prefix == "" {
		return errors.New("--out is required")
	}
	pass := ""
	if !*unencrypted {
		var err error
		if pass, err = readSecret(*passFile, "Passphrase for the new package signing key", true); err != nil {
			return fmt.Errorf("passphrase: %w (or pass --unencrypted)", err)
		}
		if pass == "" {
			return errors.New("empty passphrase; pass --unencrypted to store the key without one")
		}
	}
	sec, pub, id, err := packaging.GenerateKey(pass)
	if err != nil {
		return err
	}
	for _, p := range []string{*prefix + ".key", *prefix + ".pub"} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s exists; refusing to overwrite a key", p)
		}
	}
	if err := packaging.WriteFileAtomic(*prefix+".key", sec, 0o600); err != nil {
		return err
	}
	if err := packaging.WriteFileAtomic(*prefix+".pub", pub, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "key %s\nsecret key: %s.key\npublic key: %s.pub\nenroll it with: smcpctl trust add %s.pub --name <name> --key-id %s\n", id, *prefix, *prefix, *prefix, id)
	return nil
}

func pkgBuild(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("package build", flag.ContinueOnError)
	recipe := fs.String("recipe", "", "packaging recipe (JSON)")
	outDir := fs.String("out", "", "package directory to create")
	npmReg := fs.String("npm-registry", "", "npm registry base URL (default https://registry.npmjs.org)")
	pypi := fs.String("pypi-index", "", "PyPI base URL (default https://pypi.org)")
	node := fs.String("node", "", "absolute path of node for the probe (default PATH)")
	python := fs.String("python", "", "absolute path of python3 for the probe and pip (default PATH)")
	podman := fs.String("podman", "", "absolute path of podman for OCI probes (default PATH)")
	timeout := fs.Duration("timeout", 15*time.Minute, "overall time limit")
	verbose := fs.Bool("v", false, "show fetch and dependency installation output")
	cfgPath := fs.String("config", "", "configuration file whose profile and [runtime] table select the probe launcher (optional)")
	sandboxMode := fs.String("sandbox", "", "probe launcher: podman (rootless sandbox, no network, only the throwaway slot directories mounted) or none (default: podman when --config selects the Enforced profile, else none)")
	image := fs.String("image", "", "with --sandbox podman: image (name@sha256:...) that runs a node or python candidate")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *recipe == "" || *outDir == "" {
		return errors.New("--recipe and --out are required")
	}
	r, err := packaging.LoadRecipe(*recipe)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	logw := io.Discard
	if *verbose {
		logw = out
	}
	launcher, closeLauncher, err := probeLauncher(ctx, *cfgPath, *sandboxMode, *image, r.Server.Alias)
	if err != nil {
		return err
	}
	defer closeLauncher()
	pkg, err := packaging.Build(ctx, r, *outDir, packaging.BuildOptions{
		Fetcher: &packaging.Fetcher{NPMRegistry: *npmReg, PyPIIndex: *pypi},
		Interp:  packaging.Interpreters{Node: *node, Python: *python, Podman: *podman},
		Version: backend.Version, Python: *python, Log: logw,
		Launcher: launcher,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "built %s@%s in %s\nartifact sha256 %s\nera %s, %d tools: %s\nprobe: launcher %s, network %s, environment %v\nnext: smcpctl package sign %s --key <file>\n",
		pkg.Index.ServerID, pkg.Index.Revision, *outDir, pkg.Index.Artifact.SHA256, pkg.Manifest.Era, len(pkg.Manifest.Tools), toolNames(pkg.Manifest),
		pkg.Provenance.Probe.Launcher, pkg.Provenance.Probe.Network, pkg.Provenance.Probe.EnvNames, *outDir)
	return nil
}

// probeLauncher returns the launcher of the package build probe (FR-14.3,
// SR-3.5-1): nil (an unconfined subprocess) or, in the Enforced profile, a
// rootless Podman sandbox with no network whose only mounts are the
// candidate and its empty throwaway slot directories. The sandbox's state
// lives in a throwaway directory removed by the returned function.
func probeLauncher(ctx context.Context, cfgPath, mode, image, alias string) (pipeline.Launcher, func(), error) {
	rt := config.DefaultRuntime()
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return nil, nil, err
		}
		if mode == "" && cfg.Profile.Mode == "enforced" {
			mode = "podman"
		}
		if cfg.Runtime.Sandbox == "podman" {
			rt = cfg.Runtime
		}
	}
	switch mode {
	case "", "none":
		if image != "" {
			return nil, nil, errors.New("--image needs --sandbox podman")
		}
		return nil, func() {}, nil
	case "podman":
	default:
		return nil, nil, fmt.Errorf("--sandbox must be podman or none, not %q", mode)
	}
	if image != "" && !strings.Contains(image, "@sha256:") {
		return nil, nil, errors.New("--image must be referenced by digest (name@sha256:...)")
	}
	rt.Sandbox = "podman"
	rt.Servers = []config.RuntimeServer{{Alias: alias, Image: image, Network: "none", Scope: "shared"}}
	state, cleanup, err := packaging.ThrowawayDir("smcp-probe-state-")
	if err != nil {
		return nil, nil, err
	}
	l, err := sandbox.New(sandbox.Options{Runtime: rt, StateDir: state, Log: slog.New(slog.DiscardHandler), GrantDeclaredSlots: true})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	l.Start(ctx)
	return l, func() { l.Close(); cleanup() }, nil
}

func toolNames(m *packaging.Manifest) string {
	n := make([]string, 0, len(m.Tools))
	for _, t := range m.Tools {
		n = append(n, t.Name)
	}
	return strings.Join(n, ", ")
}

// loadSecretKey reads a minisign secret key file, prompting for or reading
// the passphrase when it is encrypted.
func loadSecretKey(keyFile, passFile string) (minisign.PrivateKey, error) {
	if keyFile == "" {
		return minisign.PrivateKey{}, errors.New("--key <file> is required")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	pass := ""
	if packaging.SecretKeyEncrypted(raw) {
		if pass, err = readSecret(passFile, "Passphrase for "+keyFile, false); err != nil {
			return minisign.PrivateKey{}, err
		}
	}
	k, err := packaging.ParseSecretKey(raw, pass)
	if err != nil {
		return minisign.PrivateKey{}, fmt.Errorf("secret key %s: %w", keyFile, err)
	}
	return k, nil
}

func pkgSign(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("package sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "minisign secret key file")
	passFile := fs.String("passphrase-file", "", "read the key passphrase from this file instead of a prompt")
	check := refuseInlineSecrets(fs)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: smcpctl package sign <dir> --key <file>")
	}
	k, err := loadSecretKey(*keyFile, *passFile)
	if err != nil {
		return err
	}
	if err := packaging.Sign(pos[0], k, time.Now()); err != nil {
		return err
	}
	fmt.Fprintf(out, "signed %s with key %s\n", filepath.Join(pos[0], packaging.IndexFile), packaging.KeyID(k.ID()))
	return nil
}

func pkgVerify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("package verify", flag.ContinueOnError)
	pubFile := fs.String("pubkey", "", "verify against this minisign public key instead of the enrolled trust anchors")
	cfgPath := fs.String("config", "smcp.toml", "configuration file (for the trust anchors)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: smcpctl package verify <dir> [--pubkey <file>]")
	}
	var keys packaging.KeyResolver
	if *pubFile != "" {
		raw, err := os.ReadFile(*pubFile)
		if err != nil {
			return err
		}
		pub, err := packaging.ParsePublicKey(raw)
		if err != nil {
			return fmt.Errorf("public key: %w", err)
		}
		keys = packaging.PublicKeyResolver(pub)
	} else {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return fmt.Errorf("%w (or pass --pubkey)", err)
		}
		a, err := packaging.LoadAnchors(cfg.State.Dir)
		if err != nil {
			return err
		}
		keys = a.Resolver()
	}
	p, err := packaging.Verify(pos[0], packaging.VerifyOptions{Keys: keys})
	if err != nil {
		return fmt.Errorf("package verification FAILED: %w", err)
	}
	fmt.Fprintf(out, "package OK: %s@%s, risk class %s, signer %s, artifact %s (%s)\n", p.Index.ServerID, p.Index.Revision, p.Manifest.HighestRisk(),
		p.Index.SignerKeyID, p.Index.Artifact.SHA256, p.Manifest.Artifact.Type)
	return nil
}

// standaloneOffline reports whether instances would run unconfined. With no
// confining launcher in this release that is always the case.
func standaloneOffline(cfg *config.Config) bool {
	rep, err := profile.Resolve(cfg.Profile.Mode, "subprocess", false, profile.DetectHost())
	return err != nil || rep.Profile == profile.Standalone
}

func pkgInstall(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("package install", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	enable := fs.Bool("enable", false, "enable the revision after importing it (Administrator)")
	alias := fs.String("alias", "", "alias to enable it under (default the manifest alias)")
	downgrade := fs.Bool("allow-downgrade", false, "authorize importing a revision lower than an installed one (SR-3-5)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: smcpctl package install <dir>")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	anchors, err := packaging.LoadAnchors(cfg.State.Dir)
	if err != nil {
		return err
	}
	p, err := packaging.Verify(pos[0], packaging.VerifyOptions{Keys: anchors.Resolver()})
	if err != nil {
		return fmt.Errorf("package verification FAILED: %w", err)
	}
	libDir := cfg.Packages.Library
	if libDir == "" {
		libDir = filepath.Join(cfg.State.Dir, "library")
	}
	dst := filepath.Join(libDir, p.Index.ServerID, p.Index.Revision)
	if _, err := os.Stat(dst); err == nil {
		fmt.Fprintf(out, "%s is already in the library\n", dst)
	} else if err := packaging.CopyPackage(pos[0], dst); err != nil {
		return err
	}
	lib, err := library.OpenConfigured(cfg, nil)
	if errors.Is(err, library.ErrLocked) {
		// smcpd holds the registry: let it import.
		if err := control([]string{"--config", *cfgPath}, out, "POST", "/api/v1/packages/scan", map[string]any{}); err != nil {
			return err
		}
		if *enable {
			return pkgState("enable", []string{"--config", *cfgPath, "--alias", *alias, p.Index.ServerID + "@" + p.Index.Revision}, out)
		}
		return nil
	}
	if err != nil {
		return err
	}
	defer lib.Close()
	rc, err := lib.Import(dst, library.ImportOptions{Actor: "smcpctl", AllowDowngrade: *downgrade})
	if err != nil {
		return fmt.Errorf("import refused: %w (receipt %s)", err, rc.File)
	}
	fmt.Fprintf(out, "imported %s@%s as verified-disabled (receipt %s)\n", rc.ServerID, rc.Revision, rc.File)
	if *enable {
		r, err := lib.Enable(rc.ServerID, rc.Revision, library.EnableOptions{Actor: "smcpctl", Alias: *alias, Standalone: standaloneOffline(cfg)})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "enabled %s as alias %q; restart smcpd to launch it\n", r.Key(), r.Alias)
	}
	return nil
}

func splitRef(s string) (string, string, error) {
	id, rev, ok := strings.Cut(s, "@")
	if !ok || !packaging.ValidID(id, rev) {
		return "", "", fmt.Errorf("%q is not <server-id>@<revision>", s)
	}
	return id, rev, nil
}

func pkgList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("package list", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	lib, err := library.OpenConfigured(cfg, nil)
	if errors.Is(err, library.ErrLocked) {
		return control([]string{"--config", *cfgPath}, out, "GET", "/api/v1/packages", nil)
	}
	if err != nil {
		return err
	}
	defer lib.Close()
	revs := lib.Revisions()
	if *asJSON {
		printJSON(out, map[string]any{"library": lib.Dir(), "revisions": revs})
		return nil
	}
	tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SERVER\tREVISION\tSTATE\tALIAS\tRISK\tTYPE\tARTIFACT\tSIGNER")
	for _, r := range revs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ServerID, r.Revision, r.State, r.Alias, r.RiskClass, r.ArtifactType, r.ArtifactSHA256[:16], r.Anchor)
	}
	return tw.Flush()
}

func pkgState(action string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("package "+action, flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	alias := fs.String("alias", "", "alias (enable only)")
	reason := fs.String("reason", "", "reason recorded with the change")
	offline := fs.Bool("offline", false, "change the state directory directly (smcpd must not be running)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: smcpctl package %s <server-id>@<revision>", action)
	}
	id, rev, err := splitRef(pos[0])
	if err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	lib, err := library.OpenConfigured(cfg, nil)
	switch {
	case errors.Is(err, library.ErrLocked) && *offline:
		return err
	case errors.Is(err, library.ErrLocked):
		body := map[string]any{}
		if action == "enable" && *alias != "" {
			body["alias"] = *alias
		}
		if action != "enable" && *reason != "" {
			body["reason"] = *reason
		}
		return control([]string{"--config", *cfgPath}, out, "POST", "/api/v1/packages/"+id+"/"+rev+"/"+action, body)
	case err != nil:
		return err
	}
	defer lib.Close()
	var r library.Revision
	if action == "enable" {
		r, err = lib.Enable(id, rev, library.EnableOptions{Actor: "smcpctl", Alias: *alias, Standalone: standaloneOffline(cfg)})
	} else {
		state := map[string]string{"disable": library.StateVerifiedDisabled, "retire": library.StateRetired}[action]
		if *reason == "" {
			*reason = "operator action (smcpctl)"
		}
		r, _, err = lib.SetState(id, rev, state, *reason, "smcpctl")
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s is %s (alias %q); the change applies when smcpd next starts\n", r.Key(), r.State, r.Alias)
	return nil
}

func pkgRevoke(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("package revoke", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	keyFile := fs.String("key", "", "minisign secret key file of an enrolled trust anchor")
	passFile := fs.String("passphrase-file", "", "read the key passphrase from this file instead of a prompt")
	reason := fs.String("reason", "", "reason for the revocation (required)")
	check := refuseInlineSecrets(fs)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if len(pos) != 1 || *reason == "" {
		return errors.New("usage: smcpctl package revoke <server-id>@<revision> --key <file> --reason <text>")
	}
	id, rev, err := splitRef(pos[0])
	if err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	k, err := loadSecretKey(*keyFile, *passFile)
	if err != nil {
		return err
	}
	libDir := cfg.Packages.Library
	if libDir == "" {
		libDir = filepath.Join(cfg.State.Dir, "library")
	}
	p, err := packaging.WriteRevocation(libDir, id, rev, *reason, k, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", p)
	lib, err := library.OpenConfigured(cfg, nil)
	if errors.Is(err, library.ErrLocked) {
		return control([]string{"--config", *cfgPath}, out, "POST", "/api/v1/packages/scan", map[string]any{})
	}
	if err != nil {
		return err
	}
	defer lib.Close()
	rep, _ := lib.Scan("smcpctl")
	if len(rep.Errors) > 0 {
		return fmt.Errorf("scan: %s", strings.Join(rep.Errors, "; "))
	}
	if !slices.Contains(rep.Revoked, id+"@"+rev) {
		fmt.Fprintf(out, "%s@%s is not imported; the entry blocks a later import\n", id, rev)
	} else {
		fmt.Fprintf(out, "%s@%s is revoked\n", id, rev)
	}
	return nil
}

func trustCmd(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(trustUsage))
	}
	fs := flag.NewFlagSet("trust "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	name := fs.String("name", "", "anchor name (add)")
	classes := fs.String("classes", "", "comma-separated risk classes the key may admit (default low,moderate)")
	expires := fs.String("expires", "365d", "expiry: a date (2027-10-16), an RFC 3339 time or a number of days (365d)")
	keyID := fs.String("key-id", "", "add: the key ID you compared with the publisher's (confirms the fingerprint; prompted for when omitted on a terminal)")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	a, err := packaging.LoadAnchors(cfg.State.Dir)
	if err != nil {
		return err
	}
	switch args[0] {
	case "add":
		if len(pos) != 1 || *name == "" {
			return errors.New("usage: smcpctl trust add <pubkey-file> --name <name> --key-id <ID> [--classes low,moderate] [--expires 365d]")
		}
		raw, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		// FR-7.10: enroll only after the administrator confirmed the
		// displayed fingerprint, with --key-id or at the prompt.
		id, sha, err := packaging.Fingerprint(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "key ID   %s\nSHA-256  %s\n", id, sha)
		confirm := strings.TrimSpace(*keyID)
		if confirm == "" {
			if !stdinIsTerminal() {
				return fmt.Errorf("compare the key ID %s with the publisher's, then pass it as --key-id to confirm", id)
			}
			fmt.Fprint(out, "Compare the key ID with the one the publisher gave you, then type it to confirm: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			confirm = strings.TrimSpace(line)
		}
		if !strings.EqualFold(confirm, id) {
			return fmt.Errorf("the confirmed key ID %q is not the key's fingerprint %s; nothing was enrolled", confirm, id)
		}
		exp, err := parseExpiry(*expires, time.Now())
		if err != nil {
			return err
		}
		var cls []string
		if *classes != "" {
			cls = strings.Split(*classes, ",")
		}
		an, err := a.Add(*name, raw, cls, exp, time.Now(), "smcpctl")
		if err != nil {
			return err
		}
		if err := a.Save(); err != nil {
			return err
		}
		fmt.Fprintf(out, "enrolled %s (key %s) for risk classes %s until %s\n", an.Name, an.KeyID, strings.Join(an.Classes, ","), an.Expires.Format(time.RFC3339))
	case "list":
		tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tKEY ID\tCLASSES\tEXPIRES")
		for _, x := range a.Anchors {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", x.Name, x.KeyID, strings.Join(x.Classes, ","), x.Expires.Format(time.RFC3339))
		}
		return tw.Flush()
	case "remove":
		if len(pos) != 1 || !a.Remove(pos[0]) {
			return errors.New("usage: smcpctl trust remove <name-or-key-id> (no such anchor)")
		}
		if err := a.Save(); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed %s\n", pos[0])
	default:
		return errors.New(strings.TrimSpace(trustUsage))
	}
	return nil
}

func parseExpiry(s string, now time.Time) (time.Time, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n <= 0 {
			return time.Time{}, fmt.Errorf("expiry %q: want a positive number of days", s)
		}
		return now.Add(time.Duration(n) * 24 * time.Hour), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(24 * time.Hour), nil
	}
	return time.Parse(time.RFC3339, s)
}
