package app

import (
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/egress"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// The library runtime is the Packages implementation smcpd passes; it
// must offer the manifest egress rules app.Start hands to the broker.
var _ interface {
	EgressRules(alias string) []packaging.EgressRule
} = (*library.Runtime)(nil)

// TestManifestLimitsAdapter: the manifest egress rules of a server become
// the Egress Broker's manifest limits with the duration in milliseconds
// (FR-5.38); a server without rules has none.
func TestManifestLimitsAdapter(t *testing.T) {
	reqtest.Partial(t, "FR-5.38")
	f := manifestLimits(func(alias string) []packaging.EgressRule {
		if alias != "web" {
			return nil
		}
		return []packaging.EgressRule{{Host: "*.example.com", Ports: []int{443}, Methods: []string{"GET"}, RequestBytes: 10, ResponseBytes: 20, TimeoutMS: 1500}}
	})
	got := f("web")
	want := egress.ManifestLimit{Host: "*.example.com", Ports: []int{443}, RequestBytes: 10, ResponseBytes: 20, Timeout: 1500 * time.Millisecond}
	if len(got) != 1 || got[0].Host != want.Host || got[0].Ports[0] != 443 || got[0].RequestBytes != 10 || got[0].ResponseBytes != 20 || got[0].Timeout != want.Timeout {
		t.Fatalf("limits %+v", got)
	}
	if f("other") != nil {
		t.Fatal("limits for a server without rules")
	}
}
