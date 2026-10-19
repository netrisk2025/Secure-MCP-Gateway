package app

import (
	"fmt"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// MetaSourceTrust is the tool _meta key a verified manifest source sets to
// the tool's CP-44 source_trust; without it a tool is untrusted.
const MetaSourceTrust = "local.smcpgw/source_trust"

// startInspection builds the E-09/E-11 inspector. When o.Filters is nil the
// built-in filters are registered on a new chain; a caller-supplied chain
// keeps only what the caller registered, plus the evidence observer. The
// metadata scan wraps o.Manifests and screens catalogs (Screen).
func (a *App) startInspection(cfg *config.Config, o *Options) error {
	opts := filters.OptionsFrom(cfg)
	opts.Evidence, opts.Log = a.Evidence, o.Log
	opts.Trust = func(c *pipeline.Call) string {
		if a.Registry == nil {
			return "untrusted"
		}
		if ref := a.Registry.Resolve(c.PublicName); ref != nil && ref.Tool != nil {
			if v, ok := ref.Tool.Meta[MetaSourceTrust].(string); ok {
				return v
			}
		}
		return "untrusted"
	}
	opts.Names = func() map[string][]string {
		out := map[string][]string{}
		if a.Registry == nil {
			return out
		}
		for alias, s := range a.Registry.Servers() {
			for _, t := range s.Tools {
				out[alias] = append(out[alias], t.Name)
			}
		}
		return out
	}
	insp, err := filters.New(opts)
	if err != nil {
		return fmt.Errorf("filters: %w", err)
	}
	if o.Filters == nil {
		o.Filters = pipeline.NewFilters()
		if err := insp.Register(o.Filters); err != nil {
			return fmt.Errorf("filters: %w", err)
		}
	} else {
		insp.Observe(o.Filters)
	}
	if o.ExtraFilters != nil {
		if err := o.ExtraFilters(o.Filters); err != nil {
			return fmt.Errorf("filters: %w", err)
		}
	}
	o.Manifests = insp.Manifests(o.Manifests)
	a.Inspector = insp
	return nil
}
