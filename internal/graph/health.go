package graph

import (
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/health"
)

// HealthCheck reports the non-critical cause graph_mirror_unavailable while
// an enabled mirror cannot reach or write the graph database, or refused to
// start (schema too new, hardening). The Gateway is then degraded; the
// mirror never gates enforcement. A disabled mirror reports nothing.
func (m *Mirror) HealthCheck() health.Check {
	return func(time.Time) []health.Cause {
		if m == nil || !m.set.Enabled {
			return nil
		}
		m.mu.Lock()
		state, msg := m.st.State, m.st.Error
		m.mu.Unlock()
		if state != StateUnavailable && state != StateRefused {
			return nil
		}
		detail := "graph mirror " + state
		if msg != "" {
			detail += ": " + msg
		}
		return []health.Cause{{Name: health.CauseGraphUnavailable, Detail: detail}}
	}
}
