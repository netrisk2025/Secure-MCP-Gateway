package main

// Operations commands: health, reload, keys, backup, restore, journal
// export, config migrate and version (docs/operations/).

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/backup"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/ops"
)

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func loadCfg(fs *flag.FlagSet, args []string) (*config.Config, string, error) {
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(*cfgPath)
	return cfg, *cfgPath, err
}

// daemonUp reports whether the control API answers.
func daemonUp(cfg *config.Config) bool {
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return false
	}
	c.http.Timeout = 3 * time.Second
	_, _, err = c.do("GET", "/admin/v1/health", nil)
	return err == nil
}

// healthCmd prints the Health & Safety Monitor report (FR-7.12) with a
// summary line that carries the release label (FR-13.10).
func healthCmd(args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "ack" {
		return healthAck(args[1:], out)
	}
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	failOn := fs.Bool("require-not-fail-closed", false, "exit with status 1 when the state is fail-closed")
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	res, status, err := c.do("GET", "/api/v1/health/status", nil)
	if status == http.StatusNotFound {
		res, _, err = c.do("GET", "/admin/v1/health", nil) // a Gateway without the monitor
	}
	if err != nil {
		return err
	}
	state, _ := res["state"].(string)
	label := ""
	if info, ok := res["info"].(map[string]any); ok {
		label, _ = info["release_label"].(string)
	} else {
		label, _ = res["release_label"].(string)
	}
	var causes []string
	switch cs := res["causes"].(type) {
	case []any:
		for _, c := range cs {
			switch v := c.(type) {
			case string:
				causes = append(causes, v)
			case map[string]any:
				causes = append(causes, fmt.Sprint(v["name"]))
			}
		}
	}
	fmt.Fprintf(out, "health: %s; causes: %s; release label: %s\n", state, strings.Join(causes, ", "), label)
	printJSON(out, res)
	if *failOn && state == "fail-closed" {
		return errors.New("gateway is fail-closed")
	}
	return nil
}

func healthAck(args []string, out io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: smcpctl health ack <cause> [--config file]")
	}
	return control(args[1:], out, "POST", "/api/v1/health/ack", map[string]any{"cause": args[0]})
}

func reloadCmd(args []string, out io.Writer) error {
	return control(args, out, "POST", "/api/v1/config/reload", map[string]any{})
}

func versionCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	short := fs.Bool("short", false, "print only the version")
	cfgPath := fs.String("config", "smcp.toml", "configuration file; when the Gateway is running its version and label are shown too")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *short {
		fmt.Fprintln(out, backend.Version)
		return nil
	}
	fmt.Fprintf(out, "smcpctl %s\n", backend.Version)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return nil //nolint:nilerr // the configuration is optional for version
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return nil //nolint:nilerr // no state directory: nothing more to show
	}
	c.http.Timeout = 3 * time.Second
	if res, _, err := c.do("GET", "/admin/v1/health", nil); err == nil {
		fmt.Fprintf(out, "smcpd %v (%v profile, %v)\n", res["version"], res["profile"], res["release_label"])
	}
	return nil
}

func keysCmd(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: smcpctl keys status|rotate")
	}
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("keys status", flag.ContinueOnError)
		cfg, _, err := loadCfg(fs, args[1:])
		if err != nil {
			return err
		}
		if daemonUp(cfg) {
			c, err := newAdminClient(cfg, true)
			if err != nil {
				return err
			}
			res, _, err := c.do("GET", "/api/v1/keys", nil)
			if err != nil {
				return err
			}
			printJSON(out, res)
			return nil
		}
		st, err := keys.ReadStatus(cfg.State.Dir, time.Now())
		if err != nil {
			return err
		}
		printJSON(out, st)
		return nil
	case "rotate":
		return keysRotate(args[1:], out)
	}
	return errors.New("usage: smcpctl keys status|rotate")
}

func keysRotate(args []string, out io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: smcpctl keys rotate tls|ca|evidence [--overlap 168h] [--finish] [--offline]")
	}
	kind := args[0]
	fs := flag.NewFlagSet("keys rotate", flag.ContinueOnError)
	overlap := fs.String("overlap", "", "ca: how long both CAs are trusted before the new one becomes active (default 168h; 0 switches at once)")
	finish := fs.Bool("finish", false, "ca: end the overlap now and activate the new CA")
	offline := fs.Bool("offline", false, "tls and ca only: rotate in the state directory while the Gateway is stopped")
	cfg, _, err := loadCfg(fs, args[1:])
	if err != nil {
		return err
	}
	if !*offline {
		c, err := newAdminClient(cfg, true)
		if err != nil {
			return err
		}
		res, _, err := c.do("POST", "/api/v1/keys/rotate", ops.RotateRequest{Kind: kind, Overlap: *overlap, Finish: *finish})
		if err != nil {
			return err
		}
		printJSON(out, res)
		return nil
	}
	if daemonUp(cfg) {
		return errors.New("the Gateway is running; rotate through it (omit --offline)")
	}
	names := ops.ListenerNames(cfg)
	switch kind {
	case "tls":
		st, err := keys.RotateLeaf(cfg.State.Dir, names...)
		if err != nil {
			return err
		}
		printJSON(out, st)
	case "ca":
		if *finish {
			st, err := keys.FinishCARotation(cfg.State.Dir, time.Now(), names...)
			if err != nil {
				return err
			}
			printJSON(out, st)
			return nil
		}
		d := keys.DefaultCAOverlap
		if *overlap != "" {
			if d, err = time.ParseDuration(*overlap); err != nil {
				return err
			}
		}
		rot, st, err := keys.BeginCARotation(cfg.State.Dir, time.Now(), d, names...)
		if err != nil {
			return err
		}
		printJSON(out, map[string]any{"rotation": rot, "tls": st})
	default:
		return errors.New("--offline rotates only tls and ca; the evidence key is rotated by the running Gateway, which writes the transition record")
	}
	return nil
}

// encryptionFlags reads the backup encryption choice.
func encryptionFlags(fs *flag.FlagSet) (pass *string, rcpt *multiFlag) {
	pass = fs.String("passphrase-file", "", "read the backup passphrase from this file (- for standard input); default: prompt")
	rcpt = &multiFlag{}
	fs.Var(rcpt, "recipient", "encrypt to this age recipient (age1...) instead of a passphrase; repeatable")
	return pass, rcpt
}

func encryption(passFile string, rcpts []string, prompt bool) (backup.Encryption, error) {
	if len(rcpts) > 0 {
		if passFile != "" {
			return backup.Encryption{}, errors.New("give --passphrase-file or --recipient, not both")
		}
		return backup.Encryption{Recipients: rcpts}, nil
	}
	if passFile == "" && !prompt {
		return backup.Encryption{}, backup.ErrUnencrypted
	}
	pw, err := readSecret(passFile, "Backup passphrase", passFile == "")
	if err != nil {
		return backup.Encryption{}, err
	}
	if pw == "" {
		return backup.Encryption{}, backup.ErrUnencrypted
	}
	return backup.Encryption{Passphrase: pw}, nil
}

func backupCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	pass, rcpt := encryptionFlags(fs)
	var optional multiFlag
	fs.Var(&optional, "optional", "add an optional part as name=path (Observation Store copy, graph dump); repeatable")
	list := fs.Bool("list", false, "list recorded backups instead of taking one")
	cfg, cfgPath, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	if *list {
		entries, err := backup.ReadIndex(cfg.Backup.Dir)
		if err != nil {
			return err
		}
		printJSON(out, map[string]any{"dir": cfg.Backup.Dir, "backups": entries})
		return nil
	}
	opt := map[string]string{}
	for _, o := range optional {
		name, path, ok := strings.Cut(o, "=")
		if !ok || name == "" || path == "" {
			return fmt.Errorf("--optional %q: want name=path", o)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		opt[name] = abs
	}
	enc, err := encryption(*pass, *rcpt, true)
	if err != nil {
		return err
	}
	res, err := takeBackup(cfg, cfgPath, enc, opt)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "backup written: %s\nsha256: %s\ncomponents: %s\n", res.Path, res.SHA256, strings.Join(res.Manifest.Components, ", "))
	return nil
}

// takeBackup asks the running Gateway for an online backup (SR-7.7-1) or,
// when it is not running, writes one directly from the state directory.
func takeBackup(cfg *config.Config, cfgPath string, enc backup.Encryption, opt map[string]string) (backup.Result, error) {
	if daemonUp(cfg) {
		c, err := newAdminClient(cfg, true)
		if err != nil {
			return backup.Result{}, err
		}
		c.http.Timeout = 10 * time.Minute
		res, _, err := c.do("POST", "/api/v1/backup", ops.BackupRequest{Passphrase: enc.Passphrase, Recipients: enc.Recipients, Optional: opt})
		if err != nil {
			return backup.Result{}, err
		}
		var r backup.Result
		if err := remarshal(res, &r); err != nil {
			return backup.Result{}, err
		}
		return r, nil
	}
	if err := enc.Check(); err != nil {
		return backup.Result{}, err
	}
	inst, _ := keys.EnsureInstallationID(cfg.State.Dir)
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return backup.Result{}, err
	}
	return backup.Create(cfg.Backup.Dir, backup.Spec{StateDir: cfg.State.Dir, ConfigPath: abs, PolicyPath: cfg.Policy.File, Optional: opt,
		InstallationID: inst, Version: backend.Version, Encryption: enc})
}

func restoreCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	archive := fs.String("archive", "", "backup archive (.age) to restore")
	passFile := fs.String("passphrase-file", "", "read the backup passphrase from this file (- for standard input); default: prompt")
	identity := fs.String("identity-file", "", "age identity file for an archive encrypted to a recipient")
	verifyOnly := fs.Bool("verify-only", false, "decrypt and verify only; change nothing")
	cfg, cfgPath, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	if *archive == "" {
		return errors.New("--archive is required")
	}
	if !*verifyOnly && daemonUp(cfg) {
		return errors.New("the Gateway is running; stop it before restoring (smcpd must not hold the state directory)")
	}
	dec := backup.Decryption{IdentityFile: *identity}
	if *identity == "" {
		if dec.Passphrase, err = readSecret(*passFile, "Backup passphrase", false); err != nil {
			return err
		}
	}
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	rep, err := backup.Restore(backup.RestoreOptions{Archive: *archive, Decryption: dec, StateDir: cfg.State.Dir, ConfigPath: abs, PolicyPath: cfg.Policy.File, VerifyOnly: *verifyOnly})
	if err != nil {
		return fmt.Errorf("restore FAILED, nothing was changed: %w", err)
	}
	printJSON(out, rep)
	if rep.Applied {
		fmt.Fprintf(out, "restored; the previous state is kept at %s\n", rep.PreviousState)
	} else {
		fmt.Fprintln(out, "archive verified; nothing was changed")
	}
	return nil
}

// journalExport copies closed segments and the anchor to a directory
// (FR-7.14, one-shot form of [evidence] export_dir).
func journalExport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("journal export", flag.ContinueOnError)
	to := fs.String("to", "", "export directory (default [evidence] export_dir)")
	cfg, _, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	if *to == "" {
		*to = cfg.Evidence.ExportDir
	}
	if *to == "" {
		return errors.New("give --to or set [evidence] export_dir")
	}
	ex := &audit.Exporter{JournalDir: filepath.Join(cfg.State.Dir, "journal"), ExportDir: *to,
		PublicKeys: map[string]string{"evidence.pub": filepath.Join(cfg.State.Dir, keys.EvidencePubFile),
			"evidence-genesis.pub": filepath.Join(cfg.State.Dir, keys.EvidenceGenesisFile)}}
	res, err := ex.Sync()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "exported %d new segments; anchor at segment %d; verify with: smcpctl journal verify --dir %s --key %s\n",
		len(res.Copied), res.AnchorSegment, filepath.Join(*to, "journal"), filepath.Join(*to, "keys", "evidence-genesis.pub"))
	return nil
}

func configMigrate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("config migrate", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := config.Migrate(*cfgPath)
	if err != nil {
		return err
	}
	if res.From == res.To {
		fmt.Fprintf(out, "configuration is at schema_version %d; nothing to migrate\n", res.To)
		return nil
	}
	fmt.Fprintf(out, "migrated %s from schema_version %d to %d; original kept as %s\n", *cfgPath, res.From, res.To, res.Backup)
	return nil
}

// verifyJournal is `smcpctl journal verify`: it starts from the evidence
// trust root and follows key-transition records (FR-17.8).
func verifyJournal(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("journal verify", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	dir := fs.String("dir", "", "journal directory (default <state>/journal)")
	anchor := fs.String("anchor", "", "anchor file (default <journal dir>.anchor)")
	keyFile := fs.String("key", "", "hex Ed25519 public key file of the first segment (default <state>/keys/evidence-genesis.pub, else evidence.pub); needs no configuration")
	strict := fs.Bool("strict", false, "treat findings (recovered segments, truncated tail) as failures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var root []byte
	if *keyFile != "" {
		k, err := keys.ReadPublicKeyFile(*keyFile)
		if err != nil {
			return err
		}
		root = k
		if *dir == "" {
			return errors.New("--key needs --dir")
		}
	} else {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		k, err := keys.LoadEvidenceTrustRoot(cfg.State.Dir)
		if err != nil {
			return err
		}
		root = k
		if *dir == "" {
			*dir = filepath.Join(cfg.State.Dir, "journal")
		}
	}
	rep, err := audit.VerifyWith(*dir, root, audit.VerifyOptions{AnchorPath: *anchor})
	if err != nil {
		return fmt.Errorf("journal verification FAILED: %w", err)
	}
	fmt.Fprintf(out, "journal OK: %d segments, %d events", rep.Segments, rep.Events)
	if rep.AnchorSegment > 0 {
		fmt.Fprintf(out, ", anchored at segment %d", rep.AnchorSegment)
	}
	if rep.Open != "" {
		fmt.Fprintf(out, " (%s is still open; its %d events are not signed yet)", rep.Open, rep.OpenEvents)
	}
	if n := len(rep.Transitions); n > 0 {
		fmt.Fprintf(out, ", %d evidence-key transitions (segments %v)", n, rep.Transitions)
	}
	fmt.Fprintln(out)
	findings := rep.Findings()
	for _, f := range findings {
		fmt.Fprintln(out, "FINDING:", f)
	}
	if *strict && len(findings) > 0 {
		return fmt.Errorf("%d findings", len(findings))
	}
	return nil
}
