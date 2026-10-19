package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Settings are the [secrets] configuration with defaults applied and paths
// resolved against the configuration directory.
type Settings struct {
	VaultDir        string
	KeySource       string
	PassphraseFile  string
	UsePolicyFile   string
	RuntimeDir      string
	RotationOverlap time.Duration
}

// DefaultOverlap is the CP-15 rotation overlap default.
const DefaultOverlap = 24 * time.Hour

// SettingsFrom returns the [secrets] settings, and false when the table is
// absent (secrets disabled).
func SettingsFrom(cfg *config.Config) (Settings, bool) {
	if cfg.Secrets == nil {
		return Settings{}, false
	}
	c := *cfg.Secrets
	res := func(p string) string {
		if p != "" && !filepath.IsAbs(p) && cfg.Dir != "" {
			return filepath.Join(cfg.Dir, p)
		}
		return p
	}
	s := Settings{VaultDir: res(c.VaultDir), KeySource: c.KeySource, PassphraseFile: res(c.PassphraseFile), UsePolicyFile: res(c.UsePolicyFile),
		RuntimeDir: res(c.RuntimeDir), RotationOverlap: c.RotationOverlap.Duration}
	if s.VaultDir == "" {
		s.VaultDir = filepath.Join(cfg.State.Dir, "vault")
	}
	if s.KeySource == "" {
		s.KeySource = KeySourceAuto
	}
	if s.RuntimeDir == "" {
		s.RuntimeDir = defaultRuntimeDir(cfg.State.Dir)
	}
	if s.RotationOverlap == 0 {
		s.RotationOverlap = DefaultOverlap
	}
	return s, true
}

// OpenVault unlocks the configured vault. passphrase supplies the
// passphrase of a passphrase-source vault; nil reads passphrase_file.
func OpenVault(s Settings, passphrase func() (string, error), o VaultOptions) (*Vault, error) {
	info, err := Inspect(s.VaultDir)
	if err != nil {
		return nil, err
	}
	if passphrase == nil {
		passphrase = func() (string, error) {
			if s.PassphraseFile == "" {
				return "", errors.New("the vault uses a passphrase; set [secrets] passphrase_file (mode 0600)")
			}
			return PassphraseFromFile(s.PassphraseFile)()
		}
	}
	ks, err := KeySourceFor(s.VaultDir, info.KeySource, passphrase)
	if err != nil {
		return nil, err
	}
	o.Overlap = s.RotationOverlap
	return Open(s.VaultDir, ks, o)
}

// Service is the running secrets element: vault, broker and control API.
// A nil *Service (secrets not configured) is valid and does nothing.
type Service struct {
	Settings Settings
	Vault    *Vault
	Broker   *Broker
	cfg      *config.Config
	log      *slog.Logger
}

// Configure opens the vault and builds the broker when [secrets] is
// configured, and plugs them into the app seams: Options.Secrets, a
// launcher wrapper for instance teardown and an evidence observer for
// emergency stop. app.Start registers the broker's mandatory filters
// (RegisterFilters) on the filter chain after the built-in E-09/E-11
// filters, so Configure leaves Options.Filters alone. It returns nil when secrets
// are not configured. injector is the Egress Broker's S1 seam, or nil.
func Configure(cfg *config.Config, o *app.Options, injector pipeline.SecretHeaderInjector, log *slog.Logger) (*Service, error) {
	s, ok := SettingsFrom(cfg)
	if !ok {
		return nil, nil
	}
	if log == nil {
		log = slog.Default()
	}
	if s.RotationOverlap < 0 || s.RotationOverlap > MaxOverlap {
		return nil, ErrInvalidOverlap
	}
	use, err := LoadUsePolicy(s.UsePolicyFile, cfg.Servers)
	if err != nil {
		return nil, fmt.Errorf("secret use policy: %w", err)
	}
	v, err := OpenVault(s, nil, VaultOptions{})
	if err != nil {
		return nil, fmt.Errorf("vault %s: %w", s.VaultDir, err)
	}
	b, err := NewBroker(BrokerOptions{Vault: v, Use: use, Servers: cfg.Servers, RuntimeDir: s.RuntimeDir, Injector: injector, Log: log})
	if err != nil {
		return nil, err
	}
	o.Secrets = b
	o.Launcher = b.WrapLauncher(o.Launcher)
	if o.Observers == nil {
		o.Observers = map[string]audit.Observer{}
	}
	o.Observers["secret-broker"] = b
	if !IsTmpfs(s.RuntimeDir) {
		log.Warn("secret files (S2, S3) are on a disk file system, not tmpfs", "runtime_dir", s.RuntimeDir)
	}
	log.Info("secret vault unlocked", "vault", v.ID(), "key_source", v.KeySource(), "secrets", len(v.List()), "use_policy", use.Revision)
	return &Service{Settings: s, Vault: v, Broker: b, cfg: cfg, log: log}, nil
}

// Attach registers the control API routes and gives the broker the
// registry's server revisions.
func (s *Service) Attach(admin Handler, reg *backend.Registry) {
	if s == nil {
		return
	}
	if reg != nil {
		s.Broker.SetRevisions(func() map[string]string {
			out := map[string]string{}
			for alias, srv := range reg.Servers() {
				out[alias] = srv.Revision
			}
			return out
		})
	}
	if admin != nil {
		s.RegisterRoutes(admin)
	}
}

// Run sweeps rotation overlaps until ctx ends (FR-6.3, FR-6.4).
func (s *Service) Run(ctx context.Context, every time.Duration) {
	if s == nil {
		return
	}
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := s.Vault.Sweep(); err != nil {
			s.log.Error("secret retirement failed", "err", err)
		} else if n > 0 {
			s.log.Info("secret versions retired", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Close withdraws every delivery.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.Broker.Close()
}

// Reference is one reference to a secret in the impact report (FR-6.12).
type Reference struct {
	UsePolicy      string   `json:"use_policy,omitempty"`
	Server         string   `json:"server"`
	ServerRevision string   `json:"server_revision,omitempty"`
	Slot           string   `json:"slot"`
	Mode           string   `json:"mode,omitempty"`
	Tools          []string `json:"tools,omitempty"`
	Source         string   `json:"source"` // use_policy or secret_env
	Active         bool     `json:"active"` // currently delivered to a running instance
}

// Impact returns every Secret Use Policy, server revision and slot that
// references a secret (FR-6.12).
func (b *Broker) Impact(name string) []Reference {
	b.mu.Lock()
	use, servers, revf := b.use, b.servers, b.revisions
	active := map[string]bool{}
	for alias, inst := range b.instances {
		for _, d := range inst.delivered {
			if d.b.Secret == name {
				active[alias+"/"+d.b.Slot] = true
			}
		}
		for slot := range inst.s2 {
			active[alias+"/"+slot] = true
		}
	}
	b.mu.Unlock()
	revs := map[string]string{}
	if revf != nil {
		revs = revf()
	}
	out := []Reference{}
	seen := map[string]bool{}
	for _, bd := range use.bindings {
		if bd.Secret != name {
			continue
		}
		k := slotKey(bd.Server, bd.Slot)
		seen[k] = true
		out = append(out, Reference{UsePolicy: bd.ID, Server: bd.Server, ServerRevision: revs[bd.Server], Slot: bd.Slot, Mode: bd.Mode, Tools: bd.Tools,
			Source: "use_policy", Active: active[k]})
	}
	for _, s := range servers {
		for env, ref := range s.SecretEnv {
			if ref == name && !seen[slotKey(s.Alias, env)] {
				out = append(out, Reference{Server: s.Alias, ServerRevision: revs[s.Alias], Slot: env, Source: "secret_env"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return slotKey(out[i].Server, out[i].Slot) < slotKey(out[j].Server, out[j].Slot) })
	return out
}
