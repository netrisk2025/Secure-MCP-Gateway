package hostile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Egress capabilities (SR-5.16-1): the Gateway delivers one-use tokens for
// each call in the tools/call _meta; a server presents one per brokered
// operation in the Smcp-Egress-Auth header.

const (
	egressAuthMeta   = "local.smcpgw/egress_auth"
	egressAuthHeader = "Smcp-Egress-Auth"
)

type egressDest struct {
	Host     string   `json:"host"`
	Ports    []int    `json:"ports"`
	Endpoint string   `json:"endpoint_env"`
	Tokens   []string `json:"tokens"`
}

// egressTokens reads the capabilities delivered with a call.
func egressTokens(meta map[string]any) []egressDest {
	raw, err := json.Marshal(meta[egressAuthMeta])
	if err != nil {
		return nil
	}
	var a struct {
		Destinations []egressDest `json:"destinations"`
	}
	_ = json.Unmarshal(raw, &a)
	return a.Destinations
}

func grantHostMatches(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix) && len(host) > len(suffix)+1
	}
	return pattern == host
}

// tokenFor returns the n-th token (0-based) of the destination that covers
// host:port, or of the endpoint variable env when env is set; "" when none.
func tokenFor(ds []egressDest, host string, port int, env string, n int) string {
	for _, d := range ds {
		ok := env != "" && d.Endpoint == env || env == "" && grantHostMatches(d.Host, host) && slices.Contains(d.Ports, port)
		if ok && n < len(d.Tokens) {
			return d.Tokens[n]
		}
	}
	return ""
}

// probeArgs are the arguments of the EGRESS fixture's fetch tool.
type probeArgs struct {
	Via     string // proxy (default), connect or endpoint
	URL     string // proxy: absolute http:// URL
	Target  string // connect: host:port
	Env     string // endpoint: the endpoint variable
	Path    string // endpoint: origin-form path
	Method  string
	Body    string
	Auth    string // Authorization header value
	Upgrade bool   // send Upgrade: websocket
	Cap     string // use (default), none, replay, second, or host:port of another destination whose token to present
}

func argString(a map[string]any, k string) string { s, _ := a[k].(string); return s }

// probeResult is what the fetch tool reports, as JSON text.
type probeResult struct {
	Status       int    `json:"status"`
	Reason       string `json:"reason,omitempty"`
	Body         string `json:"body,omitempty"`
	Error        string `json:"error,omitempty"`
	ReplayStatus int    `json:"replay_status,omitempty"`
	ReplayReason string `json:"replay_reason,omitempty"`
	Tokens       int    `json:"tokens"`
}

// egressProbe performs one brokered operation as a well-behaved server
// would, choosing which capability to present (AT-10 and SR-5.16-1
// tests).
func egressProbe(p callParams) string {
	a := probeArgs{Via: argString(p.Arguments, "via"), URL: argString(p.Arguments, "url"), Target: argString(p.Arguments, "target"), Env: argString(p.Arguments, "env"),
		Path: argString(p.Arguments, "path"), Method: argString(p.Arguments, "method"), Body: argString(p.Arguments, "body"),
		Auth: argString(p.Arguments, "auth"), Cap: argString(p.Arguments, "cap")}
	a.Upgrade, _ = p.Arguments["upgrade"].(bool)
	if a.Method == "" {
		a.Method = http.MethodGet
	}
	ds := egressTokens(p.Meta)
	var res probeResult
	for _, d := range ds {
		res.Tokens += len(d.Tokens)
	}
	host, port := "", 0
	switch a.Via {
	case "connect":
		h, ps, _ := net.SplitHostPort(a.Target)
		host = h
		port, _ = strconv.Atoi(ps)
	case "endpoint":
	default:
		u, err := url.Parse(a.URL)
		if err != nil {
			res.Error = err.Error()
			return marshalProbe(res)
		}
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
		if port == 0 {
			port = 80
		}
	}
	tok := ""
	switch {
	case a.Cap == "none":
	case a.Cap == "second":
		tok = tokenFor(ds, host, port, a.Env, 1)
	case strings.Contains(a.Cap, ":"):
		h, ps, _ := net.SplitHostPort(a.Cap)
		op, _ := strconv.Atoi(ps)
		tok = tokenFor(ds, h, op, "", 0)
	default:
		tok = tokenFor(ds, host, port, a.Env, 0)
	}
	res.Status, res.Reason, res.Body, res.Error = probeOnce(a, tok)
	if a.Cap == "replay" {
		res.ReplayStatus, res.ReplayReason, _, _ = probeOnce(a, tok)
	}
	return marshalProbe(res)
}

func marshalProbe(r probeResult) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func probeOnce(a probeArgs, tok string) (int, string, string, string) {
	if a.Via == "connect" {
		return probeConnect(a.Target, tok)
	}
	target := a.URL
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if a.Via == "endpoint" {
		base := os.Getenv(a.Env)
		if base == "" {
			return 0, "", "", "no endpoint variable " + a.Env
		}
		target = base + a.Path
		client.Transport = &http.Transport{Proxy: nil, DisableKeepAlives: true}
	} else {
		pu, err := url.Parse(os.Getenv("HTTP_PROXY"))
		if err != nil || pu.Host == "" {
			return 0, "", "", "no proxy"
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}
	}
	var body io.Reader
	if a.Body != "" {
		body = strings.NewReader(a.Body)
	}
	req, err := http.NewRequest(a.Method, target, body) // #nosec G704 -- a test probe sending to its own Egress Broker listeners
	if err != nil {
		return 0, "", "", err.Error()
	}
	if tok != "" {
		req.Header.Set(egressAuthHeader, tok)
	}
	if a.Auth != "" {
		req.Header.Set("Authorization", a.Auth)
	}
	if a.Upgrade {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
	}
	resp, err := client.Do(req) // #nosec G704 -- the client only reaches the instance's own broker proxy or endpoint
	if err != nil {
		return 0, "", "", err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, resp.Header.Get("Smcp-Egress-Reason"), string(b), ""
}

// probeConnect sends CONNECT hostport through the proxy and reports the
// status and reason; it does not start TLS.
func probeConnect(hostport, tok string) (int, string, string, string) {
	proxy := strings.TrimPrefix(os.Getenv("HTTP_PROXY"), "http://")
	if proxy == "" {
		return 0, "", "", "no proxy"
	}
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second) // #nosec G704 -- the instance's own Egress Broker proxy address
	if err != nil {
		return 0, "", "", err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	hdr := ""
	if tok != "" {
		hdr = egressAuthHeader + ": " + tok + "\r\n"
	}
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", hostport, hostport, hdr)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return 0, "", "", err.Error()
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Smcp-Egress-Reason"), "", ""
}

func init() {
	str := map[string]any{"type": "string"}
	fixtures["EGRESS"] = &fixture{
		tools: withEcho(tool("fetch", "Send one HTTP request through the Egress Broker and report the answer.", map[string]any{"type": "object",
			"properties": map[string]any{"via": str, "url": str, "target": str, "env": str, "path": str, "method": str, "body": str, "auth": str, "cap": str,
				"upgrade": map[string]any{"type": "boolean"}}})),
		handlers: map[string]handler{"fetch": func(s *server, id json.RawMessage, p callParams) { s.reply(id, text(egressProbe(p))) }},
	}
}
