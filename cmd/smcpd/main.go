// Command smcpd is the Secure MCP Gateway daemon (first vertical slice):
// harness listener with OAuth 2.1 sessions, policy decisions, dispatch to
// stdio MCP servers and a signed evidence journal.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/session"
)

func main() {
	cfgPath := flag.String("config", "smcp.toml", "configuration file (TOML)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*cfgPath, log); err != nil {
		log.Error("smcpd failed", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	evKey, err := keys.LoadEvidenceKey(cfg.State.Dir)
	if err != nil {
		return fmt.Errorf("evidence key (run `smcpctl bootstrap` first): %w", err)
	}
	snap, err := policy.Load(cfg.Policy.File)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	journal, err := audit.Open(filepath.Join(cfg.State.Dir, "journal"), evKey, audit.Options{})
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	defer journal.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg, err := backend.Start(ctx, cfg.Servers, backend.Limits{
		PerPrincipal: cfg.Limits.ToolConcurrencyPerUser, Total: cfg.Limits.ToolConcurrencyTotal, Queue: cfg.Limits.ToolQueue,
		UpstreamTimeout: cfg.Limits.UpstreamTimeout.Duration, ResultBytes: cfg.Limits.ResultBytes,
	})
	if err != nil {
		return fmt.Errorf("backend servers: %w", err)
	}
	defer reg.Close()
	for alias, s := range reg.Servers() {
		log.Info("server enabled", "alias", alias, "revision", s.Revision, "era", s.Era, "tools", len(s.Tools))
	}

	decider := policy.NewDecider(snap, cfg.Limits.PrincipalCallsPerMin)
	store := session.NewStore(cfg, decider.Snapshot)
	oauth := session.NewOAuth(cfg, store, func(ev audit.Event) { _ = journal.Record(ev) })
	gw := edge.New(cfg, store, oauth, decider, reg, journal, log)
	defer gw.Close()

	_ = journal.Record(audit.Event{Class: "gateway", Origin: "E-23", Outcome: "started", PolicyRevision: snap.Revision, PolicyStatus: "not_evaluated", Detail: map[string]any{"version": backend.Version, "listener": cfg.Listener.Address}})
	log.Info("smcpd listening", "address", cfg.Listener.Address, "mcp", cfg.ResourceURI(), "policy_revision", snap.Revision)
	err = gw.Serve(ctx)
	_ = journal.Record(audit.Event{Class: "gateway", Origin: "E-23", Outcome: "stopped", PolicyStatus: "not_evaluated"})
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
