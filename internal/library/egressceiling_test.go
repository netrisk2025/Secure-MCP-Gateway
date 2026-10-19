package library

import (
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// TestEgressCeiling: configured egress grants are checked against the
// manifest's declared egress capabilities; each exceeded dimension (host,
// port, method) is named, and grants of other aliases are ignored.
func TestEgressCeiling(t *testing.T) {
	rules := []packaging.EgressRule{
		{Host: "api.example.com", Ports: []int{443}, Methods: []string{"GET", "POST"}},
		{Host: "*.cdn.example", Ports: []int{443, 8443}, Methods: []string{"GET", "CONNECT-TLS"}},
	}
	g := func(host string, ports []int, methods ...string) config.EgressGrant {
		return config.EgressGrant{Server: "web", Host: host, Ports: ports, Methods: methods}
	}
	for _, tc := range []struct {
		grant config.EgressGrant
		want  string // "" = within the ceiling
	}{
		{g("api.example.com", []int{443}, "GET"), ""},
		{g("API.example.com.", nil, "post"), ""},
		{g("img.cdn.example", []int{8443}, "CONNECT-TLS"), ""},
		{g("*.eu.cdn.example", []int{443}, "GET"), ""},
		{g("other.example.com", []int{443}, "GET"), "host other.example.com"},
		{g("cdn.example", []int{443}, "GET"), "host cdn.example"},
		{g("*.example.com", []int{443}, "GET"), "host *.example.com"},
		{g("10.0.0.1", []int{443}, "GET"), "host 10.0.0.1"},
		{g("api.example.com", []int{8443}, "GET"), "port 8443"},
		{g("api.example.com", []int{443}, "DELETE"), "method DELETE"},
		{g("img.cdn.example", []int{8443}, "POST"), "method POST"},
	} {
		err := CheckEgressCeiling("web", []config.EgressGrant{tc.grant}, rules)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%+v: %v", tc.grant, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want) || packaging.ReasonOf(err) != ReasonEgressCeiling):
			t.Errorf("%+v: %v, want %q", tc.grant, err, tc.want)
		}
	}
	other := config.EgressGrant{Server: "else", Host: "anything.test", Methods: []string{"GET"}}
	if err := CheckEgressCeiling("web", []config.EgressGrant{other}, nil); err != nil {
		t.Fatal(err)
	}
}

// TestPackagedServerEgressCeiling: a packaged server whose configured
// grants exceed its manifest (the fixture declares no egress) is not
// started, with the reason in its binding and in the evidence.
func TestPackagedServerEgressCeiling(t *testing.T) {
	r := newRuntime(t, fixtureDesc)
	sc := config.Server{Alias: "fx", Package: "fx-id"}
	if _, err := r.rt.Resolve(sc, true); err != nil {
		t.Fatalf("without grants: %v", err)
	}
	r.rt.o.EgressGrants = []config.EgressGrant{{Server: "fx", Host: "api.example.com", Ports: []int{443}, Methods: []string{"GET"}}}
	if _, err := r.rt.Resolve(sc, true); packaging.ReasonOf(err) != ReasonEgressCeiling {
		t.Fatalf("resolve: %v", err)
	}
	rec := &audit.Memory{}
	servers, _, err := r.rt.Prepare(rec, []config.Server{sc}, pipeline.SubprocessLauncher{}, false)
	if err != nil || len(servers) != 0 {
		t.Fatalf("prepare: %v %v", servers, err)
	}
	bs := r.rt.Bindings()
	if len(bs) != 1 || bs[0].Status != "not_started" || bs[0].ReasonCode != ReasonEgressCeiling {
		t.Fatalf("bindings %+v", bs)
	}
	found := false
	for _, e := range rec.Events() {
		if e.Outcome == "server_not_started" && e.ReasonCode == ReasonEgressCeiling {
			found = true
		}
	}
	if !found {
		t.Fatal("no server_not_started evidence")
	}
}
