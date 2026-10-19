package app

import (
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/egress"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// manifestLimits adapts the verified manifests' egress rules to the Egress
// Broker's manifest limit source (FR-5.38).
func manifestLimits(rules func(alias string) []packaging.EgressRule) egress.ManifestLimits {
	return func(server string) []egress.ManifestLimit {
		rs := rules(server)
		if len(rs) == 0 {
			return nil
		}
		out := make([]egress.ManifestLimit, 0, len(rs))
		for _, r := range rs {
			out = append(out, egress.ManifestLimit{Host: r.Host, Ports: r.Ports, RequestBytes: r.RequestBytes, ResponseBytes: r.ResponseBytes,
				Timeout: time.Duration(r.TimeoutMS) * time.Millisecond})
		}
		return out
	}
}
