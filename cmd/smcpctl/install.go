package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	linuxpkg "github.com/ethan03805/secure-mcp-gateway/packaging/linux"
)

// installHealthWait bounds how long install waits for the started Gateway's
// control API.
const installHealthWait = 60 * time.Second

// installer performs `smcpctl install` (FR-13.4 to FR-13.6). Every host
// interaction goes through its fields so that tests can run both profiles
// and both service managers with temporary roots and fake commands.
type installer struct {
	goos   string
	home   string
	getenv func(string) string
	uid    int
	root   string // prefix of Enforced-profile host paths (tests); "" in production
	binDir string
	out    io.Writer

	// run executes a command, streaming its output to out; ok reports only
	// whether a query command exits 0.
	run func(argv ...string) error
	ok  func(argv ...string) bool
	// chownTree gives a directory tree to a user and group (Enforced).
	chownTree func(dir, owner, group string) error
	// chown gives one file to a user and group (Enforced).
	chown func(path, owner, group string) error

	noStart    bool
	healthWait time.Duration
	boot       bootstrapOpts
}

func installCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	profile := fs.String("profile", "standalone", "platform profile: standalone (macOS, Linux) or enforced (Linux, as root)")
	binDir := fs.String("bin-dir", "", "directory holding smcpd, smcpctl and smcp-refserver (default: the directory of this smcpctl)")
	noStart := fs.Bool("no-start", false, "write the service unit but do not load or start it, and skip the health check")
	wait := fs.Duration("health-timeout", installHealthWait, "how long to wait for the started Gateway to answer")
	o := bootstrapOpts{}
	fs.StringVar(&o.adminFile, "admin-password-file", "", "read the administrator password from this file (mode 0600 or stricter) instead of a prompt")
	fs.StringVar(&o.approverFile, "approver-password-file", "", "read the Session Approver password from this file (mode 0600 or stricter) instead of a prompt")
	fs.BoolVar(&o.useToken, "bootstrap-token", false, "set no administrator password now; print a one-use token for `smcpctl admin redeem`")
	fs.StringVar(&o.sandbox, "sandbox", "", "directory the reference server may read")
	fs.IntVar(&o.port, "port", 8443, "harness listener port on 127.0.0.1")
	fs.IntVar(&o.adminPort, "admin-port", 8444, "control API listener port on 127.0.0.1")
	fs.IntVar(&o.metricsPort, "metrics-port", -1, "metrics endpoint port on 127.0.0.1 (default admin port + 1; 0 turns metrics off)")
	fs.StringVar(&o.notify, "notify", "auto", "approval desktop notifications: auto, off, osascript, terminal-notifier or notify-send")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		// Never echo the argument: it may be a password (SR-7.5-2).
		return errPasswordArg
	}
	in := newInstaller(out)
	in.noStart, in.healthWait, in.boot = *noStart, *wait, o
	if *binDir != "" {
		in.binDir = *binDir
	}
	switch *profile {
	case "standalone":
		return in.standalone()
	case "enforced":
		return in.enforced()
	default:
		return fmt.Errorf("--profile must be standalone or enforced, not %q", *profile)
	}
}

func newInstaller(out io.Writer) *installer {
	in := &installer{goos: runtime.GOOS, home: homeDir(), getenv: os.Getenv, uid: os.Getuid(), root: hostRoot, out: out,
		healthWait: installHealthWait}
	if exe, err := os.Executable(); err == nil {
		in.binDir = filepath.Dir(exe)
	}
	in.run = func(argv ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
		}
		return nil
	}
	in.ok = func(argv ...string) bool { return runQuiet(argv...) == nil }
	in.chown = chownPath
	in.chownTree = func(dir, owner, group string) error {
		return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return chownPath(p, owner, group)
		})
	}
	return in
}

func chownPath(p, owner, group string) error {
	u, err := user.Lookup(owner)
	if err != nil {
		return err
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(g.Gid)
	return os.Lchown(p, uid, gid)
}

func (in *installer) step(verb, what string) { fmt.Fprintf(in.out, "%s %s\n", verb, what) }

func verb(created bool) string {
	if created {
		return "created"
	}
	return "present"
}

// ensureDir creates p with mode when absent. An existing directory is left
// as it is (its mode is reported when it differs).
func (in *installer) ensureDir(p string, mode os.FileMode) error {
	st, err := os.Stat(p)
	switch {
	case err == nil && st.IsDir():
		if st.Mode().Perm() != mode {
			in.step("present", fmt.Sprintf("directory %s (mode %04o, CP-46 says %04o)", p, st.Mode().Perm(), mode))
		} else {
			in.step("present", "directory "+p)
		}
		return nil
	case err == nil:
		return fmt.Errorf("%s exists and is not a directory", p)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if err := os.MkdirAll(p, mode); err != nil {
		return err
	}
	if err := os.Chmod(p, mode); err != nil { // MkdirAll is subject to the umask
		return err
	}
	in.step("created", "directory "+p)
	return nil
}

// ensureFile writes content to p unless p already holds exactly that
// content, and returns "present", "created" or "updated".
func ensureFile(p string, content []byte, mode os.FileMode) (string, error) {
	old, err := os.ReadFile(p)
	if err == nil && bytes.Equal(old, content) {
		return "present", nil
	}
	v := "created"
	if err == nil {
		v = "updated"
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return v, nil
}

// standaloneLayout is the CP-46 per-user layout.
type standaloneLayout struct {
	cfgDir, stateDir, logDir, runtimeDir, sandbox string
	unit                                          string // launchd plist or systemd user unit
}

func (in *installer) xdg(name, def string) string {
	if v := in.getenv(name); v != "" && filepath.IsAbs(v) {
		return v
	}
	return filepath.Join(in.home, def)
}

func (in *installer) layout() (standaloneLayout, error) {
	switch in.goos {
	case "darwin":
		base := filepath.Join(in.home, "Library", "Application Support", "smcp-gateway")
		return standaloneLayout{
			cfgDir:   filepath.Join(base, "config"),
			stateDir: filepath.Join(base, "state"),
			logDir:   filepath.Join(in.home, "Library", "Logs", "smcp-gateway"),
			sandbox:  filepath.Join(base, "sandbox"),
			unit:     filepath.Join(in.home, "Library", "LaunchAgents", launchdLabel+".plist"),
		}, nil
	case "linux":
		state := filepath.Join(in.xdg("XDG_STATE_HOME", ".local/state"), "smcp-gateway")
		l := standaloneLayout{
			cfgDir:   filepath.Join(in.xdg("XDG_CONFIG_HOME", ".config"), "smcp-gateway"),
			stateDir: state,
			logDir:   filepath.Join(state, "log"),
			sandbox:  filepath.Join(in.xdg("XDG_DATA_HOME", ".local/share"), "smcp-gateway", "sandbox"),
			unit:     filepath.Join(in.xdg("XDG_CONFIG_HOME", ".config"), "systemd", "user", systemdUnit),
		}
		if rt := in.getenv("XDG_RUNTIME_DIR"); rt != "" && filepath.IsAbs(rt) {
			l.runtimeDir = filepath.Join(rt, "smcp-gateway")
		}
		return l, nil
	}
	return standaloneLayout{}, fmt.Errorf("the Standalone profile is installed on macOS and Linux, not %s", in.goos)
}

// standaloneConfigPath is where install writes the Standalone
// configuration on this host, or "" when the OS has no Standalone layout.
func standaloneConfigPath() string {
	in := &installer{goos: runtime.GOOS, home: homeDir(), getenv: os.Getenv}
	l, err := in.layout()
	if err != nil {
		return ""
	}
	return filepath.Join(l.cfgDir, "smcp.toml")
}

// installedConfigPath returns the configuration that `smcpctl install`
// wrote on this host (Enforced first, then Standalone), or "".
func installedConfigPath() string {
	for _, p := range []string{filepath.Join(hostRoot, "/etc/smcp/smcp.toml"), standaloneConfigPath()} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (in *installer) needBinaries(names ...string) error {
	for _, n := range names {
		st, err := os.Stat(filepath.Join(in.binDir, n))
		if err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("%s not found in %s (pass --bin-dir); nothing was changed", n, in.binDir)
		}
	}
	return nil
}

func (in *installer) standalone() error {
	l, err := in.layout()
	if err != nil {
		return err
	}
	if in.binDir, err = filepath.Abs(in.binDir); err != nil {
		return err
	}
	if err := in.needBinaries("smcpd", "smcp-refserver"); err != nil {
		return err
	}
	dirs := []string{l.cfgDir, l.stateDir, l.logDir}
	if l.runtimeDir != "" {
		dirs = append(dirs, l.runtimeDir)
	}
	for _, d := range dirs {
		if err := in.ensureDir(d, 0o700); err != nil {
			return err
		}
	}

	o := in.boot
	o.dir, o.stateDir, o.quiet = l.cfgDir, l.stateDir, true
	if o.sandbox == "" {
		o.sandbox = l.sandbox
	}
	if o.refserver == "" {
		o.refserver = filepath.Join(in.binDir, "smcp-refserver")
	}
	o.extraConfig = fmt.Sprintf(`
# Written by smcpctl install (FR-13.6). The Standalone profile runs servers
# unconfined; health reports degraded with cause unconfined.
[profile]
mode = "standalone"

[log]
file = %q
`, filepath.Join(l.logDir, "smcpd.log"))
	res, err := runBootstrap(o, in.out)
	if err != nil {
		return err
	}
	in.step(verb(res.keysCreated), "keys and TLS certificates in "+res.stateDir)
	in.step(verb(res.cfgCreated), "configuration "+res.cfgPath)
	in.step(verb(res.polCreated), "policy "+res.polPath)
	cfg, err := config.Load(res.cfgPath)
	if err != nil {
		return err
	}
	if cfg.Profile.Mode != "standalone" {
		fmt.Fprintf(in.out, "note: %s selects profile mode %q; install does not change an existing configuration\n", res.cfgPath, cfg.Profile.Mode)
	}

	smcpd := filepath.Join(in.binDir, "smcpd")
	var unit []byte
	if in.goos == "darwin" {
		unit = launchdPlist(smcpd, res.cfgPath, l.logDir)
	} else {
		unit = systemdUserUnit(smcpd, res.cfgPath)
	}
	uv, err := ensureFile(l.unit, unit, 0o644)
	if err != nil {
		return err
	}
	in.step(uv, "service unit "+l.unit)

	if in.noStart {
		in.step("skipped", "service start and health check (--no-start)")
	} else {
		if in.goos == "darwin" {
			err = in.loadLaunchd(l.unit, uv)
		} else {
			err = in.startSystemdUser(uv)
		}
		if err != nil {
			return err
		}
		if err := in.verifyHealth(cfg); err != nil {
			return err
		}
	}
	fmt.Fprintf(in.out, `
This installation is not enforced (Standalone profile): MCP servers run
unconfined as your user, health reports degraded with cause unconfined, and
the release label is "not enforced".

Configuration: %s
Check health:  smcpctl health --config %q
Remove:        smcpctl uninstall --config %q
`, res.cfgPath, res.cfgPath, res.cfgPath)
	return nil
}

func (in *installer) loadLaunchd(plist, unitVerb string) error {
	domain := "gui/" + strconv.Itoa(in.uid)
	target := domain + "/" + launchdLabel
	loaded := in.ok("launchctl", "print", target)
	switch {
	case loaded && unitVerb == "updated":
		_ = in.run("launchctl", "bootout", target)
		if err := in.run("launchctl", "bootstrap", domain, plist); err != nil {
			return err
		}
		in.step("updated", "launchd agent "+launchdLabel+" (reloaded)")
	case loaded:
		in.step("present", "launchd agent "+launchdLabel+" (loaded)")
	default:
		if err := in.run("launchctl", "bootstrap", domain, plist); err != nil {
			return err
		}
		in.step("created", "launchd agent "+launchdLabel+" (loaded)")
	}
	return nil
}

func (in *installer) startSystemdUser(unitVerb string) error {
	sc := func(a ...string) []string { return append([]string{"systemctl", "--user"}, a...) }
	if unitVerb != "present" {
		if err := in.run(sc("daemon-reload")...); err != nil {
			return err
		}
	}
	if in.ok(sc("is-enabled", "--quiet", systemdUnit)...) {
		in.step("present", "enabled "+systemdUnit+" (user)")
	} else {
		if err := in.run(sc("enable", "--quiet", systemdUnit)...); err != nil {
			return err
		}
		in.step("created", "enabled "+systemdUnit+" (user)")
	}
	active := in.ok(sc("is-active", "--quiet", systemdUnit)...)
	switch {
	case active && unitVerb == "updated":
		if err := in.run(sc("restart", systemdUnit)...); err != nil {
			return err
		}
		in.step("updated", "started "+systemdUnit+" (user, restarted)")
	case active:
		in.step("present", "started "+systemdUnit+" (user)")
	default:
		if err := in.run(sc("start", systemdUnit)...); err != nil {
			return err
		}
		in.step("created", "started "+systemdUnit+" (user)")
	}
	return nil
}

// verifyHealth waits for the control API and refuses a fail-closed state.
func (in *installer) verifyHealth(cfg *config.Config) error {
	deadline := time.Now().Add(in.healthWait)
	for !daemonUp(cfg) {
		if time.Now().After(deadline) {
			return fmt.Errorf("the Gateway did not answer on %s within %s; see its log (%s)", cfg.AdminURL(), in.healthWait, cfg.Log.File)
		}
		time.Sleep(250 * time.Millisecond)
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	res, status, err := c.do("GET", "/api/v1/health/status", nil)
	if status == http.StatusNotFound {
		res, _, err = c.do("GET", "/admin/v1/health", nil)
	}
	if err != nil {
		return err
	}
	state, _ := res["state"].(string)
	fmt.Fprintf(in.out, "health: %s\n", state)
	if state == "fail-closed" {
		return errors.New("the Gateway is fail-closed; smcpctl health lists the causes")
	}
	return nil
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// launchdPlist is the launchd user agent of the Standalone profile on macOS.
func launchdPlist(smcpd, cfg, logDir string) []byte {
	return fmt.Appendf(nil, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Secure MCP Gateway, Standalone profile (not enforced). Written by smcpctl install. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>--config</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>Umask</key>
	<integer>63</integer>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, launchdLabel, xmlText(smcpd), xmlText(cfg), xmlText(filepath.Join(logDir, "launchd.log")), xmlText(filepath.Join(logDir, "launchd.log")))
}

// systemdQuote quotes one word for an ExecStart= line.
func systemdQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `%`, `%%`)
	return `"` + s + `"`
}

// systemdUserUnit is the systemd user unit of the Standalone profile on
// Linux.
func systemdUserUnit(smcpd, cfg string) []byte {
	return fmt.Appendf(nil, `# Secure MCP Gateway, Standalone profile (not enforced): a systemd user unit.
# Written by smcpctl install. Servers run unconfined as this user. To keep
# the Gateway running after logout: loginctl enable-linger "$USER".
[Unit]
Description=Secure MCP Gateway (standalone profile, not enforced)
Documentation=https://github.com/ethan03805/Secure-MCP-Gateway/blob/main/docs/install.md

[Service]
Type=simple
ExecStart=%s --config %s
Restart=on-failure
RestartSec=5s
TimeoutStopSec=60s
UMask=0077

[Install]
WantedBy=default.target
`, systemdQuote(smcpd), systemdQuote(cfg))
}

// Enforced-profile host paths (CP-46), relative to installer.root.
const (
	enforcedConfig    = "/etc/smcp/smcp.toml"
	enforcedState     = "/var/lib/smcp/state"
	enforcedPolicyDir = "/var/lib/smcp/policy"
	enforcedSandbox   = "/srv/smcp/sandbox"
	enforcedLog       = "/var/log/smcp/smcpd.log"
	enforcedBin       = "/usr/local/bin"
)

func (in *installer) host(p string) string {
	if in.root == "" {
		return p
	}
	return filepath.Join(in.root, p)
}

// enforced installs the Enforced profile (FR-13.5): install-enforced.sh
// (embedded) checks every prerequisite before it changes the host, then
// creates the identities, subordinate ranges, directories, nftables table,
// AppArmor profile and systemd units; install then bootstraps the state as
// smcp-core's, writes /etc/smcp/smcp.toml and starts the units.
func (in *installer) enforced() error {
	if in.goos != "linux" {
		return fmt.Errorf("the Enforced profile needs Linux (this host is %s); nothing was changed. Use --profile standalone", in.goos)
	}
	var err error
	if in.binDir, err = filepath.Abs(in.binDir); err != nil {
		return err
	}
	if err := in.needBinaries("smcpd", "smcpctl", "smcp-refserver"); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "smcp-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := linuxpkg.Extract(tmp); err != nil {
		return err
	}
	if err := in.run("bash", filepath.Join(tmp, "install-enforced.sh"), "--bin-dir", in.binDir); err != nil {
		return fmt.Errorf("install-enforced.sh stopped (its output above names the cause): %w", err)
	}

	cfgPath := in.host(enforcedConfig)
	if _, err := os.Stat(cfgPath); err == nil {
		in.step("present", "configuration "+cfgPath)
	} else {
		if err := in.writeEnforcedConfig(cfgPath); err != nil {
			return err
		}
		in.step("created", "configuration "+cfgPath)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if in.noStart {
		in.step("skipped", "service start and health check (--no-start)")
	} else {
		if in.ok("systemctl", "is-active", "--quiet", systemdUnit) {
			in.step("present", "started "+systemdUnit)
		} else {
			if err := in.run("systemctl", "start", nftUnit, systemdUnit); err != nil {
				return err
			}
			in.step("created", "started "+systemdUnit)
		}
		if err := in.verifyHealth(cfg); err != nil {
			return err
		}
	}
	fmt.Fprintf(in.out, `
Enforced profile installed. smcpd runs as smcp-core under %s and starts each
server in a rootless Podman container of the server identity smcp-srv. The release label is "enforced" only
for a build whose AT-01 to AT-21 acceptance evidence passed.

Check the host:  sudo -u smcp-core XDG_RUNTIME_DIR=/run/smcp smcpctl runtime doctor --config %s
Check health:    sudo -u smcp-core smcpctl health --config %s
`, systemdUnit, enforcedConfig, enforcedConfig)
	return nil
}

func (in *installer) writeEnforcedConfig(cfgPath string) error {
	policyDir, stateDir, sandbox := in.host(enforcedPolicyDir), in.host(enforcedState), in.host(enforcedSandbox)
	if err := in.ensureDir(policyDir, 0o700); err != nil {
		return err
	}
	if err := in.ensureDir(filepath.Dir(sandbox), 0o755); err != nil {
		return err
	}
	if err := in.ensureDir(sandbox, 0o755); err != nil {
		return err
	}
	o := in.boot
	o.dir, o.stateDir, o.quiet = policyDir, stateDir, true
	o.policyFile = filepath.Join(policyDir, "policy.json")
	o.sandbox = sandbox
	o.refserver = in.host(filepath.Join(enforcedBin, "smcp-refserver"))
	if o.notify == "" || o.notify == "auto" {
		o.notify = "off" // a system service has no desktop session
	}
	o.extraConfig = fmt.Sprintf(`
# Written by smcpctl install (FR-13.5).
[profile]
mode = "enforced"

[runtime]
sandbox = "podman"
# Servers run in the rootless Podman of the CP-46 server identity
# (packaging/linux/setup-server-identity.sh prepares it).
run_as = "smcp-srv"
shared_dir = "/var/lib/smcp/srv"

[[runtime.server]]
alias = "ref"
[[runtime.server.mount]]
source = %q

[log]
file = %q
`, sandbox, in.host(enforcedLog))
	res, err := runBootstrap(o, in.out)
	if err != nil {
		return err
	}
	in.step(verb(res.keysCreated), "keys and TLS certificates in "+res.stateDir)
	in.step(verb(res.polCreated), "policy "+res.polPath)
	// smcpd runs as smcp-core and owns its state and policy.
	for _, d := range []string{stateDir, policyDir} {
		if err := in.chownTree(d, "smcp-core", "smcp"); err != nil {
			return fmt.Errorf("chown %s: %w", d, err)
		}
	}
	body, err := os.ReadFile(res.cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, body, 0o640); err != nil {
		return err
	}
	if err := in.chown(cfgPath, "root", "smcp"); err != nil {
		return fmt.Errorf("chown %s: %w", cfgPath, err)
	}
	return os.Remove(res.cfgPath)
}
