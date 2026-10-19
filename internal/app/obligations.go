package app

import (
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// obligationContext returns the FR-3.12 obligations a permit carries from
// outside the policy document: the observation objects in force (from
// Options.ObservationContext), the result size limit and upstream timeout,
// the server's egress and secret grants, and its runtime profile.
func (a *App) obligationContext(o Options) func(server string) policy.ObligationContext {
	cfg := a.Config
	runtime := a.Profile.Profile
	if o.Launcher != nil {
		runtime += "/" + o.Launcher.Name()
	}
	slots, _ := o.Secrets.(interface{ GrantedSlots(server string) []string })
	return func(server string) policy.ObligationContext {
		c := policy.ObligationContext{SizeLimit: cfg.Limits.ResultBytes, Timeout: cfg.Limits.UpstreamTimeout.Duration, RuntimeProfile: runtime}
		if o.ObservationContext != nil {
			c.AuditProfile, c.ObservationPolicy, c.AnomalyResponse = o.ObservationContext()
		}
		if a.Egress != nil {
			c.EgressGrants = a.Egress.GrantHosts(server)
		}
		if slots != nil {
			c.SecretGrants = slots.GrantedSlots(server)
		}
		return c
	}
}
