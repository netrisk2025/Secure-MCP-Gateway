package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/backup"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/ops"
)

// CP-47 upgrade bounds.
const (
	upgradeHealthWait = 60 * time.Second
	migrationLimit    = 120 * time.Second
)

// releaseBinaries are installed by upgrade when the release has them.
var releaseBinaries = []string{"smcpd", "smcpctl", "smcp-refserver", "smcp-connect", "smcp-stdio", "smcp-session"}

type upgrader struct {
	cfg        *config.Config
	cfgPath    string
	release    string // the downloaded release directory
	pubkey     string // minisign release key
	binDir     string
	enc        backup.Encryption
	dec        backup.Decryption
	svc        service
	healthWait time.Duration
	out        io.Writer

	installed []string
	backup    string
	from, to  string
}

func upgradeCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	release := fs.String("release", "", "directory with the downloaded release: smcp_<version>_checksums.txt, its .minisig and the archive for this platform")
	pubkey := fs.String("pubkey", releasePublicKey, "minisign public key the checksum file must be signed with (default: the release key in SECURITY.md)")
	binDir := fs.String("bin-dir", "", "directory of the installed binaries (default: the directory of this smcpctl)")
	pass, rcpt := encryptionFlags(fs)
	identity := fs.String("identity-file", "", "age identity matching --recipient, used to restore the pre-upgrade backup on rollback")
	startCmd := fs.String("start-cmd", "", "shell command that starts the Gateway (default: the installed launchd or systemd unit)")
	stopCmd := fs.String("stop-cmd", "", "shell command that stops the Gateway (default: the installed launchd or systemd unit)")
	wait := fs.Duration("health-timeout", upgradeHealthWait, "how long to wait for the new version to leave fail-closed (CP-47)")
	cfg, cfgPath, err := loadCfg(fs, args)
	if err != nil {
		return err
	}
	if *release == "" {
		return errors.New("--release is required")
	}
	u := &upgrader{cfg: cfg, release: *release, pubkey: *pubkey, binDir: *binDir, healthWait: *wait, out: out,
		svc: service{startCmd: *startCmd, stopCmd: *stopCmd}}
	if u.cfgPath, err = filepath.Abs(cfgPath); err != nil {
		return err
	}
	u.svc.env = []string{"SMCP_CONFIG=" + u.cfgPath}
	if u.binDir == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		u.binDir = filepath.Dir(exe)
	}
	if u.enc, err = encryption(*pass, *rcpt, true); err != nil {
		return err
	}
	if len(u.enc.Recipients) > 0 {
		if *identity == "" {
			return errors.New("--recipient needs --identity-file so that a rollback can restore the pre-upgrade backup")
		}
		u.dec = backup.Decryption{IdentityFile: *identity}
	} else {
		u.dec = backup.Decryption{Passphrase: u.enc.Passphrase}
	}
	return u.run()
}

func (u *upgrader) say(format string, a ...any) { fmt.Fprintf(u.out, "upgrade: "+format+"\n", a...) }

func (u *upgrader) run() error {
	// 1. Verify the release as install.sh does (FR-13.2): the minisign
	// signature of the checksum file, then the archive's SHA-256; extract
	// it only after both pass.
	goos, goarch := hostPlatform()
	rel, err := verifyReleaseDir(u.release, u.pubkey, goos, goarch, "")
	if err != nil {
		return fmt.Errorf("release verification failed, nothing changed: %w", err)
	}
	defer os.RemoveAll(rel.Dir)
	u.say("release verified: signature of smcp_%s_checksums.txt and checksum of %s", rel.Version, rel.Archive)
	u.release = rel.Dir
	u.to = binaryVersion(filepath.Join(u.release, "smcpctl"))
	u.from = u.runningVersion()
	u.say("upgrading from %s to %s", orUnknown(u.from), orUnknown(u.to))

	// 2. Encrypted backup (FR-17.6), online when the Gateway runs.
	res, err := takeBackup(u.cfg, u.cfgPath, u.enc, nil)
	if err != nil {
		return fmt.Errorf("pre-upgrade backup failed, nothing changed: %w", err)
	}
	u.backup = res.Path
	u.say("backup written: %s (sha256 %s)", res.Path, res.SHA256)

	// 3. Stop dispatch, then the old process.
	if daemonUp(u.cfg) {
		if c, err := newAdminClient(u.cfg, true); err == nil {
			if _, _, err := c.do("POST", "/admin/v1/stop", map[string]any{"reason": "upgrade"}); err != nil {
				return fmt.Errorf("stop dispatch: %w", err)
			}
		}
		u.say("dispatch stopped")
	}
	if err := u.stopAndWait(); err != nil {
		return err
	}

	// 4. Install the new binaries, keeping the previous ones as .prev.
	if err := u.install(); err != nil {
		return u.rollback("binary install failed: " + err.Error())
	}
	u.say("installed %s", strings.Join(u.installed, ", "))

	// 5. Configuration and state migrations with the new binary.
	if err := u.migrate(); err != nil {
		return u.rollback("migration failed: " + err.Error())
	}

	// 6. Start the new version and wait for a state other than fail-closed.
	if err := u.svc.start(); err != nil {
		return u.rollback("start failed: " + err.Error())
	}
	if err := u.waitHealthy(u.to); err != nil {
		return u.rollback(err.Error())
	}
	u.say("upgrade complete; the previous binaries are kept as <name>.prev in %s", u.binDir)
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// binaryVersion runs `<smcpctl> version --short`.
func binaryVersion(smcpctl string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, smcpctl, "version", "--short").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (u *upgrader) runningVersion() string {
	c, err := newAdminClient(u.cfg, true)
	if err != nil {
		return ""
	}
	c.http.Timeout = 3 * time.Second
	res, _, err := c.do("GET", "/admin/v1/health", nil)
	if err != nil {
		return ""
	}
	v, _ := res["version"].(string)
	return v
}

func (u *upgrader) stopAndWait() error {
	if !daemonUp(u.cfg) {
		return nil
	}
	if err := u.svc.stop(); err != nil {
		return fmt.Errorf("stop the Gateway: %w", err)
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if !daemonUp(u.cfg) {
			return nil
		}
	}
	return errors.New("the Gateway did not stop within 30 s")
}

func copyExec(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil { //nolint:gosec // installed binaries are executable
		return err
	}
	return os.Rename(tmp, dst)
}

func (u *upgrader) install() error {
	for _, name := range releaseBinaries {
		src := filepath.Join(u.release, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(u.binDir, name)
		if _, err := os.Stat(dst); err == nil {
			if err := copyExec(dst, dst+".prev"); err != nil {
				return err
			}
		}
		if err := copyExec(src, dst); err != nil {
			return err
		}
		u.installed = append(u.installed, name)
	}
	return nil
}

func (u *upgrader) restoreBinaries() []error {
	var errs []error
	for _, name := range u.installed {
		dst := filepath.Join(u.binDir, name)
		if _, err := os.Stat(dst + ".prev"); err == nil {
			if err := copyExec(dst+".prev", dst); err != nil {
				errs = append(errs, err)
			}
		} else if err := os.Remove(dst); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (u *upgrader) migrate() error {
	ctx, cancel := context.WithTimeout(context.Background(), migrationLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(u.binDir, "smcpctl"), "config", "migrate", "--config", u.cfgPath)
	cmd.Stdout, cmd.Stderr = u.out, u.out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("exceeded the CP-47 limit of %s", migrationLimit)
		}
		return err
	}
	return nil
}

// waitHealthy waits for the Gateway to answer with a state other than
// fail-closed and, when known, the expected version.
func (u *upgrader) waitHealthy(version string) error {
	deadline := time.Now().Add(u.healthWait)
	last := "no answer"
	for time.Now().Before(deadline) {
		if c, err := newAdminClient(u.cfg, true); err == nil {
			c.http.Timeout = 3 * time.Second
			if res, _, err := c.do("GET", "/admin/v1/health", nil); err == nil {
				state, _ := res["state"].(string)
				v, _ := res["version"].(string)
				last = fmt.Sprintf("state %s, version %s", state, v)
				if state != "fail-closed" && (version == "" || v == version) {
					u.say("Gateway answers: %s", last)
					return nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("the Gateway did not leave fail-closed within %s (%s)", u.healthWait, last)
}

// rollback restores the previous binaries and the pre-upgrade backup,
// leaves the upgrade_rolled_back marker for the previous version to record
// and starts it (FR-13.8).
func (u *upgrader) rollback(reason string) error {
	u.say("rolling back: %s", reason)
	_ = u.stopAndWait()
	errs := u.restoreBinaries()
	rep, err := backup.Restore(backup.RestoreOptions{Archive: u.backup, Decryption: u.dec, StateDir: u.cfg.State.Dir, ConfigPath: u.cfgPath, PolicyPath: u.cfg.Policy.File,
		GraphBestEffort: true, GraphTimeout: 30 * time.Second})
	if err != nil {
		errs = append(errs, fmt.Errorf("restore %s: %w", u.backup, err))
	} else {
		u.say("pre-upgrade backup restored; the state of the failed attempt is kept at %s", rep.PreviousState)
	}
	ev := ops.UpgradeEvent{Outcome: "upgrade_rolled_back", FromVersion: u.from, ToVersion: u.to, Reason: reason, Backup: u.backup, Time: time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.Marshal(ev)
	if err := keys.WriteFileAtomic(filepath.Join(u.cfg.State.Dir, ops.UpgradeEventFile), b, 0o600); err != nil {
		errs = append(errs, err)
	}
	if err := u.svc.start(); err != nil {
		errs = append(errs, fmt.Errorf("start the previous version: %w", err))
	} else if err := u.waitHealthy(""); err != nil {
		errs = append(errs, fmt.Errorf("previous version: %w", err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("upgrade failed (%s) and the rollback had errors: %w", reason, errors.Join(errs...))
	}
	return fmt.Errorf("upgrade rolled back: %s; the previous version is running", reason)
}
