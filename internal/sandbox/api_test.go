package sandbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

type muxRouter struct{ mux *http.ServeMux }

func (m muxRouter) Handle(p string, h http.HandlerFunc) { m.mux.Handle(p, h) }

func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestRuntimeAPI(t *testing.T) {
	reqtest.Partial(t, "FR-5.35")
	h := newHarness(t, testRuntime())
	p, err := h.l.Launch(context.Background(), h.spec("api"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	connect(t, p)
	mux := http.NewServeMux()
	api := &API{Launcher: h.l, Actor: func(*http.Request) string { return "admin:alice" },
		Doctor: func(context.Context) []Check {
			return []Check{{ID: "os", Status: CheckPass}, {ID: "nftables", Status: CheckFail}}
		}}
	api.Register(muxRouter{mux})

	code, body := do(t, mux, "GET", "/api/v1/runtime", "")
	if code != 200 || body["launcher"] != "podman" || body["confined"] != true || body["gateway_id"] != h.l.GatewayID() {
		t.Fatalf("summary %d %v", code, body)
	}
	code, body = do(t, mux, "GET", "/api/v1/runtime/instances", "")
	list, _ := body["instances"].([]any)
	if code != 200 || len(list) != 1 {
		t.Fatalf("instances %d %v", code, body)
	}
	id := list[0].(map[string]any)["instance_id"].(string)
	code, body = do(t, mux, "GET", "/api/v1/runtime/instances/"+id, "")
	if code != 200 || body["instance"].(map[string]any)["launch_spec"] == nil {
		t.Fatalf("show %d %v", code, body)
	}
	if code, _ = do(t, mux, "GET", "/api/v1/runtime/instances/nope", ""); code != 404 {
		t.Fatalf("unknown instance %d", code)
	}
	if code, _ = do(t, mux, "POST", "/api/v1/runtime/instances/"+id+"/kill", `{"bogus":1}`); code != 400 {
		t.Fatalf("bad body %d", code)
	}
	code, body = do(t, mux, "POST", "/api/v1/runtime/instances/"+id+"/kill", `{"reason":"test"}`)
	if code != 200 || body["state"] != StateKilled {
		t.Fatalf("kill %d %v", code, body)
	}
	name := h.l.Instances()[0].Container
	eventually(t, 3*time.Second, "kill", func() bool { return strings.Contains(h.kills(name), "KILL") })
	e := findEvent(h.mem.Events(), "instance_killed", ReasonOperatorKill)
	if e == nil || e.Detail.(map[string]any)["actor"] != "admin:alice" || e.Detail.(map[string]any)["reason"] != "test" {
		t.Fatalf("kill evidence %+v", e)
	}
	if code, _ = do(t, mux, "POST", "/api/v1/runtime/instances/"+id+"/kill", `{"reason":"again"}`); code != 404 {
		t.Fatalf("second kill %d", code)
	}
	code, body = do(t, mux, "GET", "/api/v1/runtime/doctor", "")
	if code != 200 || body["ready"] != false || len(body["checks"].([]any)) != 2 {
		t.Fatalf("doctor %d %v", code, body)
	}
}

func TestRuntimeAPIWithoutSandbox(t *testing.T) {
	mux := http.NewServeMux()
	(&API{Doctor: func(context.Context) []Check { return nil }}).Register(muxRouter{mux})
	code, body := do(t, mux, "GET", "/api/v1/runtime", "")
	if code != 200 || body["sandbox"] != "none" || body["confined"] != false {
		t.Fatalf("%d %v", code, body)
	}
	if code, body = do(t, mux, "GET", "/api/v1/runtime/instances", ""); code != 200 || len(body["instances"].([]any)) != 0 {
		t.Fatalf("%d %v", code, body)
	}
	if code, _ = do(t, mux, "POST", "/api/v1/runtime/instances/x/kill", `{"reason":""}`); code != 404 {
		t.Fatalf("%d", code)
	}
}
