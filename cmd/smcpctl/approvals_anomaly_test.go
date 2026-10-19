package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestApprovalsShowAnomalyEvidence covers the anomaly part of the FR-3.18
// evidence in `smcpctl approvals show`: the band, contributing feature,
// z-score and snapshot the control API returns are printed (before, the
// command printed "none reported" for every approval).
func TestApprovalsShowAnomalyEvidence(t *testing.T) {
	reqtest.Partial(t, "FR-3.18")
	var out bytes.Buffer
	printEvidence(&out, map[string]any{
		"id": "a1", "state": "pending", "public_name": "ref_echo", "server": "ref", "tool": "echo",
		"anomaly": map[string]any{"band": "critical", "contributing_feature": "request_bytes", "z_score": 160.94859066750217, "snapshot_id": "s1", "context": "principal=p|tool=echo"},
	})
	if !strings.Contains(out.String(), "band critical, feature request_bytes, z-score 160.95, snapshot s1") {
		t.Fatalf("anomaly evidence missing:\n%s", out.String())
	}
	out.Reset()
	printEvidence(&out, map[string]any{"id": "a2", "state": "pending"})
	if !strings.Contains(out.String(), "none reported") {
		t.Fatalf("an approval without anomaly evidence:\n%s", out.String())
	}
}
