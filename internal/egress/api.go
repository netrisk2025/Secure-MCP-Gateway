package egress

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Routes is the part of the control API server the broker registers on;
// *adminapi.Server implements it with the control API's authentication,
// origin and CSRF checks.
type Routes interface {
	Handle(pattern string, h http.HandlerFunc)
}

// Register adds the /api/v1/egress routes (docs/api/egress.md). A nil
// broker registers routes that report the broker as disabled, so clients
// get a clear answer instead of 404.
func (b *Broker) Register(r Routes) {
	r.Handle("GET /api/v1/egress", b.apiStatus)
	r.Handle("GET /api/v1/egress/grants", b.apiGrants)
	r.Handle("GET /api/v1/egress/connections", b.apiConnections)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func disabled(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "egress_disabled",
		"message": "the Egress Broker is not enabled; set [egress] enabled = true"}})
}

// StatusView is the body of GET /api/v1/egress.
type StatusView struct {
	Enabled  bool `json:"enabled"`
	Enforced int  `json:"enforced_instances"`
	Advisory int  `json:"advisory_instances"`
	// RequireCapability reports whether each operation needs a one-use
	// capability of the current call (SR-5.16-1).
	RequireCapability bool           `json:"require_capability"`
	Instances         []InstanceInfo `json:"instances"`
	Limits            LimitsView     `json:"limits"`
}

// LimitsView is Limits in JSON form.
type LimitsView struct {
	RequestBytes      int64  `json:"request_bytes"`
	ResponseBytes     int64  `json:"response_bytes"`
	OperationTimeout  string `json:"operation_timeout"`
	DialTimeout       string `json:"dial_timeout"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	BytesPerMinute    int64  `json:"bytes_per_minute"`
}

func (b *Broker) apiStatus(w http.ResponseWriter, _ *http.Request) {
	if b == nil {
		disabled(w)
		return
	}
	v := StatusView{Enabled: true, Instances: b.Instances(), RequireCapability: b.o.RequireCapability}
	for _, in := range v.Instances {
		if in.Enforced {
			v.Enforced++
		} else {
			v.Advisory++
		}
	}
	l := b.limits
	v.Limits = LimitsView{RequestBytes: l.RequestBytes, ResponseBytes: l.ResponseBytes, OperationTimeout: l.OperationTimeout.String(),
		DialTimeout: l.DialTimeout.String(), RequestsPerMinute: l.RequestsPerMinute, BytesPerMinute: l.BytesPerMinute}
	writeJSON(w, http.StatusOK, v)
}

// GrantView is one grant in GET /api/v1/egress/grants.
type GrantView struct {
	Server        string   `json:"server"`
	Host          string   `json:"host"`
	Ports         []int    `json:"ports"`
	Methods       []string `json:"methods"`
	Class         string   `json:"class"`
	Addresses     []string `json:"addresses,omitempty"`
	EndpointEnv   string   `json:"endpoint_env,omitempty"`
	RequestBytes  int64    `json:"request_bytes"`
	ResponseBytes int64    `json:"response_bytes"`
	Timeout       string   `json:"timeout"`
}

func (b *Broker) apiGrants(w http.ResponseWriter, r *http.Request) {
	if b == nil {
		disabled(w)
		return
	}
	servers := b.o.Servers
	if s := r.URL.Query().Get("server"); s != "" {
		servers = []string{s}
	}
	out := []GrantView{}
	for _, s := range servers {
		for _, g := range b.o.Grants.Grants(s) {
			lim := b.limits.effective(g)
			gv := GrantView{Server: g.Server, Host: g.Host, Ports: g.Ports, Methods: g.Methods, Class: g.Class, EndpointEnv: g.EndpointEnv,
				RequestBytes: lim.RequestBytes, ResponseBytes: lim.ResponseBytes, Timeout: lim.OperationTimeout.String()}
			for _, a := range g.Addresses {
				gv.Addresses = append(gv.Addresses, a.String())
			}
			out = append(out, gv)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

func (b *Broker) apiConnections(w http.ResponseWriter, r *http.Request) {
	if b == nil {
		disabled(w)
		return
	}
	q := r.URL.Query()
	limit := 100
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 10000 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "bad_limit", "message": "limit must be 1 to 10000"}})
			return
		}
		limit = n
	}
	var since time.Time
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "bad_since", "message": "since must be an RFC 3339 time"}})
			return
		}
		since = t
	}
	server, decision := q.Get("server"), q.Get("decision")
	out := []Record{}
	for _, rec := range b.Recent() {
		if len(out) >= limit {
			break
		}
		if (server != "" && rec.Server != server) || (decision != "" && rec.Decision != decision) || rec.Time.Before(since) {
			continue
		}
		out = append(out, rec)
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": out})
}
