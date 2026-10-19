package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The loopback metrics endpoint answers only requests addressed to a
// loopback name, so a web page using DNS rebinding cannot read it.
func TestMetricsHostCheck(t *testing.T) {
	h := New(nil, Sources{}).Handler()
	for host, want := range map[string]int{
		"127.0.0.1:9464":    http.StatusOK,
		"[::1]:9464":        http.StatusOK,
		"localhost:9464":    http.StatusOK,
		"127.0.0.1":         http.StatusOK,
		"evil.example:9464": http.StatusMisdirectedRequest,
		"attacker.test":     http.StatusMisdirectedRequest,
		"192.168.1.10:9464": http.StatusMisdirectedRequest,
		"":                  http.StatusMisdirectedRequest,
	} {
		req := httptest.NewRequest("GET", "/metrics", nil)
		req.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("Host %q: %d, want %d", host, w.Code, want)
		}
	}
}
