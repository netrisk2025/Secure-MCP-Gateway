package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// Service-manager names expected by upgrade and uninstall (FR-12.5): a
// launchd user agent on macOS; on Linux the units of
// packaging/linux/install-enforced.sh (system units smcpd.service and
// smcp-nftables.service) or a smcpd.service user unit in the Standalone
// profile.
const (
	launchdLabel = "com.smcp.gateway"
	systemdUnit  = "smcpd.service"
	nftUnit      = "smcp-nftables.service"
)

// hostRoot prefixes every host path that upgrade and uninstall touch
// outside the installation (unit files); tests point it at a temporary
// directory. When set, uninstall also leaves nftables, LSM profiles and
// service identities alone.
var hostRoot = ""

// service starts and stops the Gateway. Explicit commands (--start-cmd,
// --stop-cmd, run with sh -c) win over the detected service manager.
type service struct {
	startCmd, stopCmd string
	env               []string
}

type unitFile struct {
	path   string
	kind   string // launchd, systemd-user, systemd-system, systemd-aux (removed, never started)
	exists bool
}

func homeDir() string { h, _ := os.UserHomeDir(); return h }

// unitFiles lists the service definitions the Gateway may be installed with.
func unitFiles() []unitFile {
	var out []unitFile
	add := func(p, kind string) {
		if hostRoot != "" {
			p = filepath.Join(hostRoot, p)
		}
		_, err := os.Stat(p)
		out = append(out, unitFile{p, kind, err == nil})
	}
	switch runtime.GOOS {
	case "darwin":
		add(filepath.Join(homeDir(), "Library", "LaunchAgents", launchdLabel+".plist"), "launchd")
	case "linux":
		cfgHome := os.Getenv("XDG_CONFIG_HOME")
		if cfgHome == "" {
			cfgHome = filepath.Join(homeDir(), ".config")
		}
		add(filepath.Join(cfgHome, "systemd", "user", systemdUnit), "systemd-user")
		add(filepath.Join("/etc/systemd/system", systemdUnit), "systemd-system")
		add(filepath.Join("/etc/systemd/system", nftUnit), "systemd-aux")
		add("/etc/smcp/smcp.nft", "nft-ruleset")
	}
	return out
}

func installedUnit() *unitFile {
	for _, u := range unitFiles() {
		if u.exists && (u.kind == "launchd" || u.kind == "systemd-user" || u.kind == "systemd-system") {
			return &u
		}
	}
	return nil
}

func (s service) run(ctx context.Context, cmdline string) error {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdline)
	cmd.Env = append(os.Environ(), s.env...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func managerCmd(u *unitFile, action string) []string {
	switch u.kind {
	case "launchd":
		target := "gui/" + strconv.Itoa(os.Getuid()) + "/" + launchdLabel
		if action == "stop" {
			return []string{"launchctl", "bootout", target}
		}
		return []string{"launchctl", "bootstrap", "gui/" + strconv.Itoa(os.Getuid()), u.path}
	case "systemd-user":
		return []string{"systemctl", "--user", action, systemdUnit}
	default:
		return []string{"systemctl", action, systemdUnit}
	}
}

var errNoManager = errors.New("no service manager unit is installed for the Gateway; pass --start-cmd and --stop-cmd")

func (s service) do(action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch {
	case action == "start" && s.startCmd != "":
		return s.run(ctx, s.startCmd)
	case action == "stop" && s.stopCmd != "":
		return s.run(ctx, s.stopCmd)
	}
	u := installedUnit()
	if u == nil {
		return errNoManager
	}
	argv := managerCmd(u, action)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %w", argv, err)
	}
	return nil
}

func (s service) start() error { return s.do("start") }
func (s service) stop() error  { return s.do("stop") }
