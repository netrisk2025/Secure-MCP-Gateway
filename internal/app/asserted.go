package app

import (
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
)

// recordAssertion records text a server instance asserted (stderr, a
// JSON-RPC error message, a notification) as a server_asserted event
// attributed to the instance (SR-6.18-1). The event is not a policy
// decision and never changes the call it may relate to.
func (a *App) recordAssertion(x backend.Assertion) {
	if a.Evidence == nil {
		return
	}
	d := map[string]any{"server": x.Server, "instance": x.Instance, "text": x.Text}
	if x.Method != "" {
		d["method"] = x.Method
	}
	if x.Kind == backend.AssertError {
		d["code"] = x.Code
	}
	if x.Truncated > 0 {
		d["truncated_bytes"] = x.Truncated
	}
	if x.Skipped > 0 {
		d["skipped_bytes"] = x.Skipped
	}
	if x.Dropped > 0 {
		d["dropped"] = x.Dropped
	}
	if err := a.Evidence.Record(audit.Event{Class: "server_asserted", Origin: "E-15", Outcome: x.Kind, ServerRevision: x.ServerRevision,
		PolicyStatus: "not_evaluated", Detail: d}); err != nil && a.log != nil {
		a.log.Warn("server-asserted evidence not recorded", "server", x.Server, "err", err)
	}
}
