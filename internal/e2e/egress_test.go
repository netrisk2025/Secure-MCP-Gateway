package e2e

import (
	"strings"
	"testing"
)

// TestEgressBrokerWiring: with [egress] enabled the Gateway attaches each
// backend instance to the broker at launch (advisory in the standalone
// profile) and serves /api/v1/egress behind control-API authentication.
func TestEgressBrokerWiring(t *testing.T) {
	f := start(t, `
[egress]
enabled = true
requests_per_minute = 30
[[egress.grant]]
server = "t"
host = "api.example.com"
ports = [443]
methods = ["GET", "CONNECT-TLS"]
`)
	ins := f.app.Egress.Instances()
	if len(ins) != 1 || ins[0].Server != "t" || ins[0].Enforced || !strings.HasPrefix(ins[0].Proxy, "http://127.0.0.1:") {
		t.Fatalf("instances %+v", ins)
	}
	if st, _ := f.admin("GET", "/api/v1/egress", "", nil); st != 401 {
		t.Fatalf("unauthenticated: %d", st)
	}
	st, body := f.admin("GET", "/api/v1/egress", f.operator, nil)
	if st != 200 || body["enabled"] != true || body["advisory_instances"] != float64(1) {
		t.Fatalf("%d %v", st, body)
	}
	if lim, _ := body["limits"].(map[string]any); lim["requests_per_minute"] != float64(30) {
		t.Fatalf("limits %v", body["limits"])
	}
	st, body = f.admin("GET", "/api/v1/egress/grants", f.operator, nil)
	gs, _ := body["grants"].([]any)
	if st != 200 || len(gs) != 1 || gs[0].(map[string]any)["host"] != "api.example.com" {
		t.Fatalf("%d %v", st, body)
	}
	f.stop()
	if len(f.app.Egress.Instances()) != 0 {
		t.Fatal("instances survive shutdown")
	}
}

func TestEgressDisabledByDefault(t *testing.T) {
	f := start(t, "")
	if f.app.Egress != nil {
		t.Fatal("broker started without [egress] enabled")
	}
	st, body := f.admin("GET", "/api/v1/egress", f.operator, nil)
	if e, _ := body["error"].(map[string]any); st != 404 || e["code"] != "egress_disabled" {
		t.Fatalf("%d %v", st, body)
	}
}
