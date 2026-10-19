package library

import (
	"log/slog"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// OpenConfigured opens the library named by a Gateway configuration.
func OpenConfigured(cfg *config.Config, log *slog.Logger) (*Library, error) {
	return Open(Options{StateDir: cfg.State.Dir, Dir: cfg.Packages.Library, Log: log})
}

// Interpreters returns the configured runtime paths.
func Interpreters(cfg *config.Config) packaging.Interpreters {
	return packaging.Interpreters{Node: cfg.Packages.Node, Python: cfg.Packages.Python, Podman: cfg.Packages.Podman}
}

// OpenRuntime opens the library and its Gateway runtime from the
// configuration (smcpd).
func OpenRuntime(cfg *config.Config, log *slog.Logger) (*Runtime, error) {
	lib, err := OpenConfigured(cfg, log)
	if err != nil {
		return nil, err
	}
	return NewRuntime(lib, RuntimeOptions{Interp: Interpreters(cfg), RequireSigned: cfg.Packages.RequireSigned,
		ScanInterval: cfg.Packages.ScanInterval.Duration, Log: log, EgressGrants: egressGrants(cfg)}), nil
}

// egressGrants returns the configured egress grants when the Egress Broker
// is enabled; without it no grant takes effect.
func egressGrants(cfg *config.Config) []config.EgressGrant {
	if !cfg.Egress.Enabled {
		return nil
	}
	return cfg.Egress.Grants
}
