package library

import (
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// ReasonEgressCeiling refuses a packaged server whose configured egress
// grants exceed the egress capabilities its signed manifest declares.
const ReasonEgressCeiling = "EGRESS_EXCEEDS_MANIFEST"

// CheckEgressCeiling checks the [[egress.grant]] entries of one server
// alias against the egress capability ceiling of its manifest
// (capabilities.egress). A grant is within the ceiling when one manifest
// rule covers its host (the same name, or a rule "*.suffix" covering the
// name or a narrower wildcard) and, for every granted port and method,
// a covering rule lists both. The error names the first grant that
// exceeds the ceiling and the exceeded dimension: host, port or method.
func CheckEgressCeiling(alias string, grants []config.EgressGrant, rules []packaging.EgressRule) error {
	for i, g := range grants {
		if g.Server != alias {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(g.Host), ".")
		var cover []packaging.EgressRule
		for _, r := range rules {
			if ruleCovers(strings.ToLower(r.Host), host) {
				cover = append(cover, r)
			}
		}
		if len(cover) == 0 {
			return errf(ReasonEgressCeiling, "egress.grant[%d] for %s exceeds the manifest's egress capabilities: host %s is not declared", i, alias, host)
		}
		ports := g.Ports
		if len(ports) == 0 {
			ports = []int{443}
		}
		for _, p := range ports {
			if !slices.ContainsFunc(cover, func(r packaging.EgressRule) bool { return slices.Contains(r.Ports, p) }) {
				return errf(ReasonEgressCeiling, "egress.grant[%d] for %s exceeds the manifest's egress capabilities: port %d of %s is not declared", i, alias, p, host)
			}
			for _, m := range g.Methods {
				m = strings.ToUpper(m)
				if !slices.ContainsFunc(cover, func(r packaging.EgressRule) bool { return slices.Contains(r.Ports, p) && slices.Contains(r.Methods, m) }) {
					return errf(ReasonEgressCeiling, "egress.grant[%d] for %s exceeds the manifest's egress capabilities: method %s on %s port %d is not declared", i, alias, m, host, p)
				}
			}
		}
	}
	return nil
}

// ruleCovers reports whether the manifest host rule covers the grant host
// (both lower case; a grant host may itself be a wildcard).
func ruleCovers(rule, host string) bool {
	if rule == host {
		return true
	}
	suffix, ok := strings.CutPrefix(rule, "*.")
	if !ok {
		return false
	}
	name := strings.TrimPrefix(host, "*.")
	return strings.HasSuffix(name, "."+suffix) && len(name) > len(suffix)+1
}
