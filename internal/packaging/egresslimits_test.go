package packaging_test

import (
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestManifestEgressLimitsSchema: an egress rule may declare request
// size, response size and duration limits (FR-5.38), each a positive
// integer, the duration at most an hour.
func TestManifestEgressLimitsSchema(t *testing.T) {
	reqtest.Partial(t, "FR-5.38")
	rule := func(extra map[string]any) map[string]any {
		m := fixtureManifest(t)
		r := map[string]any{"host": "api.example.com", "ports": []any{443}, "methods": []any{"GET"}}
		for k, v := range extra {
			r[k] = v
		}
		m["capabilities"].(map[string]any)["egress"] = []any{r}
		return m
	}
	if err := parse(t, rule(map[string]any{"request_bytes": 1000, "response_bytes": 2000, "timeout_ms": 300})); err != nil {
		t.Fatalf("limits: %v", err)
	}
	for name, extra := range map[string]map[string]any{
		"zero request":   {"request_bytes": 0},
		"negative":       {"response_bytes": -1},
		"too long":       {"timeout_ms": 3600001},
		"fractional":     {"timeout_ms": 1.5},
		"unknown member": {"requests_per_minute": 5},
	} {
		if err := parse(t, rule(extra)); reason(err) != packaging.ReasonManifestSchema {
			t.Errorf("%s: %v", name, err)
		}
	}
}
