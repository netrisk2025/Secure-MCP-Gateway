package egress

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// hopHeaders are removed in both directions (RFC 9110 §7.6.1), together
// with any header named in Connection.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripHop(h http.Header) {
	for _, f := range h.Values("Connection") {
		for _, name := range strings.Split(f, ",") {
			if name = textproto.TrimString(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// proxyHandler is the instance's forward proxy.
func (b *Broker) proxyHandler(in *instance) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			b.serveConnect(in, w, r)
			return
		}
		rec := b.newRecord(in, ModeHTTP, r.Method)
		if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.User != nil {
			b.refuse(w, rec, ReasonBadRequest, "send absolute http:// URLs to this proxy, and use CONNECT for https")
			return
		}
		host, err := canonicalHost(r.URL.Hostname(), false)
		if err != nil {
			b.refuse(w, rec, ReasonBadRequest, err.Error())
			return
		}
		port, err := portOf(r.URL.Port(), 80)
		if err != nil {
			b.refuse(w, rec, ReasonBadRequest, err.Error())
			return
		}
		target := &url.URL{Scheme: "http", Host: urlHost(host, port, 80), Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		b.forward(w, r, rec, target, false)
	})
}

// endpointHandler is a per-destination endpoint: origin-form requests are
// sent to https://host:port with the broker originating TLS.
func (b *Broker) endpointHandler(in *instance, env, host string, port int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := b.newRecord(in, ModeEndpoint, r.Method)
		if r.Method == http.MethodConnect || r.URL.IsAbs() {
			b.refuse(w, rec, ReasonBadRequest, "this endpoint serves only "+env+"; send origin-form requests")
			return
		}
		target := &url.URL{Scheme: "https", Host: urlHost(host, port, 443), Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		b.forward(w, r, rec, target, true)
	})
}

// authorize finds the current grant for one operation, spends the
// operation's egress capability and applies the request-rate limit.
func (b *Broker) authorize(rec *Record, host string, port int, method string, h http.Header) (Grant, error) {
	rec.Host, rec.Port = host, port
	g, ok, known := match(b.o.Grants.Grants(rec.Server), host, port, method)
	if !ok {
		if known {
			return Grant{}, refused(ReasonMethod, "%s is not granted for %s", method, joinHostPort(host, port))
		}
		return Grant{}, refused(ReasonNoGrant, "%s is not an egress destination of server %s", joinHostPort(host, port), rec.Server)
	}
	rec.Grant = g.Host
	// SR-5.16-1: a one-use capability of the current call, bound to this
	// instance and grant, is spent before anything else happens.
	if err := b.consume(rec, g, h); err != nil {
		return Grant{}, err
	}
	if !b.limiter(rec.Server).requests.AllowN(b.o.Now(), 1) {
		return Grant{}, refused(ReasonRateLimited, "request rate limit of server %s reached", rec.Server)
	}
	return g, nil
}

// publicFetch applies the public-fetch method profile (SR-5.19-1): HTTPS
// GET only, without a body, Authorization header or upgrade.
func publicFetch(r *http.Request) error {
	switch {
	case r.Method != http.MethodGet:
		return refused(ReasonPublicFetchProfile, "public-fetch permits only GET")
	case r.ContentLength != 0 || len(r.TransferEncoding) > 0:
		return refused(ReasonPublicFetchProfile, "public-fetch permits no request body")
	case r.Header.Get("Authorization") != "":
		return refused(ReasonPublicFetchProfile, "public-fetch permits no Authorization header")
	}
	return nil
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// forward performs one HTTP operation. Endpoints follow redirects within
// the instance's grants, re-validating each target, at most MaxRedirects
// times (SR-5.15-1); the forward proxy returns redirects to the instance,
// whose next request is authorized as a new operation.
func (b *Broker) forward(w http.ResponseWriter, r *http.Request, rec *Record, target *url.URL, follow bool) {
	rec.Path = target.Path
	if r.Header.Get("Upgrade") != "" {
		b.refuse(w, rec, ReasonBadRequest, "protocol upgrades (WebSocket) are not brokered")
		return
	}
	host, _ := canonicalHost(target.Hostname(), false)
	port, _ := portOf(target.Port(), defaultPort(target.Scheme))
	g, err := b.authorize(rec, host, port, r.Method, r.Header)
	if err != nil {
		rf := asRefusal(err)
		b.refuse(w, rec, rf.reason, rf.detail)
		return
	}
	if g.Class == ClassPublicFetch {
		if !follow {
			b.refuse(w, rec, ReasonPublicFetchProfile, "public-fetch grants are served only through their endpoint")
			return
		}
		if err := publicFetch(r); err != nil {
			rf := asRefusal(err)
			b.refuse(w, rec, rf.reason, rf.detail)
			return
		}
	}
	lim := b.opLimits(rec, g, host, port)
	if r.ContentLength > lim.RequestBytes {
		b.refuse(w, rec, ReasonRequestTooLarge, "request body larger than the limit")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), lim.OperationTimeout)
	defer cancel()
	sl := b.limiter(rec.Server)
	var up, down atomic.Int64
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.URL = target
	out.Host = target.Host
	stripHop(out.Header)
	out.Header.Del("Cookie") // SR-5.17-1
	out.Header.Del(AuthHeader)
	out.Close = true
	// SR-5.8-2: the secret-fingerprint filter over URL, headers and body,
	// before the S1 header is inserted.
	if where, err := b.scanRequest(out, target, lim.RequestBytes); err != nil {
		b.refuse(w, rec, ReasonBadRequest, "request body unreadable")
		return
	} else if where != "" {
		b.refuse(w, rec, ReasonSecretDetected, "a registered secret appears in the request "+where)
		return
	}
	if out.Body != nil && out.Body != http.NoBody {
		out.Body = io.NopCloser(&meteredReader{r: out.Body, limit: lim.RequestBytes, n: &up, lim: sl.bytes, now: b.o.Now, tooLarge: ReasonRequestTooLarge})
	}
	if err := b.authorized(rec); err != nil {
		rec.Decision = DecisionDenied
		b.refuse(w, rec, ReasonEvidenceFailed, "evidence journal unavailable")
		return
	}
	var resp *http.Response
	for hop := 0; ; hop++ {
		st := &dialState{grant: g, rec: rec}
		out = out.WithContext(context.WithValue(ctx, dialKey{}, st))
		rec.Injected = b.applyHeaders(out, rec.Server, host, rec.Port, out.URL.Scheme) // S1 (inject.go)
		resp, err = b.transport.RoundTrip(out)
		if err != nil {
			rf := asRefusal(err)
			b.fail(w, rec, &up, &down, rf)
			return
		}
		if !follow || !isRedirect(resp.StatusCode) || (out.Method != http.MethodGet && out.Method != http.MethodHead) {
			break
		}
		loc, lerr := out.URL.Parse(resp.Header.Get("Location"))
		if lerr != nil || resp.Header.Get("Location") == "" {
			break
		}
		resp.Body.Close()
		if hop >= MaxRedirects {
			b.fail(w, rec, &up, &down, &refusal{ReasonRedirect, "more than 3 redirects"})
			return
		}
		nh, herr := canonicalHost(loc.Hostname(), false)
		np, perr := portOf(loc.Port(), defaultPort(loc.Scheme))
		if loc.Scheme != "https" || herr != nil || perr != nil {
			b.fail(w, rec, &up, &down, &refusal{ReasonRedirect, "redirect to a non-https or malformed URL"})
			return
		}
		ng, ok, _ := match(b.o.Grants.Grants(rec.Server), nh, np, out.Method)
		if !ok {
			b.fail(w, rec, &up, &down, &refusal{ReasonRedirect, "redirect to " + joinHostPort(nh, np) + ", which is not granted"})
			return
		}
		rec.Redirects = hop + 1
		next := out.Clone(ctx)
		next.URL = loc
		next.Host = loc.Host
		next.Body = nil
		next.ContentLength = 0
		if nh != host {
			next.Header.Del("Authorization")
		}
		out, g, host = next, ng, nh
		rec.Host, rec.Port, rec.Grant, rec.Path = nh, np, ng.Host, loc.Path
	}
	defer resp.Body.Close()
	if resp.ContentLength > lim.ResponseBytes {
		b.fail(w, rec, &up, &down, &refusal{ReasonResponseTooLarge, "declared response larger than the limit"})
		return
	}
	h := w.Header()
	for k, vs := range resp.Header {
		h[k] = vs
	}
	stripHop(h)
	h.Del("Set-Cookie") // SR-5.17-1
	h.Del("Set-Cookie2")
	rec.Status = resp.StatusCode
	w.WriteHeader(resp.StatusCode)
	body := &meteredReader{r: resp.Body, limit: lim.ResponseBytes, n: &down, lim: sl.bytes, now: b.o.Now, tooLarge: ReasonResponseTooLarge}
	_, cerr := io.Copy(w, body)
	rec.BytesUp, rec.BytesDown = up.Load(), down.Load()
	if cerr != nil {
		rf := asRefusal(cerr)
		b.finish(rec, rf.reason, rf.detail)
		// Headers are sent: abort the connection so the instance cannot
		// mistake a truncated body for a complete one.
		panic(http.ErrAbortHandler)
	}
	b.finish(rec, "", "")
}

// fail ends an authorized operation that did not produce a response.
func (b *Broker) fail(w http.ResponseWriter, rec *Record, up, down *atomic.Int64, rf *refusal) {
	rec.BytesUp, rec.BytesDown = up.Load(), down.Load()
	if rf.reason == ReasonAddressRefused || rf.reason == ReasonDNSFailed || rf.reason == ReasonRedirect || rf.reason == ReasonNoGrant {
		rec.Decision = DecisionDenied
	}
	b.refuse(w, rec, rf.reason, rf.detail)
}

// serveConnect runs an HTTPS tunnel: authorize host and port, resolve and
// validate the address, check that the TLS SNI names the granted host,
// then splice bytes without terminating TLS.
func (b *Broker) serveConnect(in *instance, w http.ResponseWriter, r *http.Request) {
	rec := b.newRecord(in, ModeConnect, MethodConnect)
	h, p, err := net.SplitHostPort(r.Host)
	if err != nil {
		b.refuse(w, rec, ReasonBadRequest, "CONNECT needs host:port")
		return
	}
	host, err := canonicalHost(h, false)
	if err != nil {
		b.refuse(w, rec, ReasonBadRequest, err.Error())
		return
	}
	port, err := portOf(p, 0)
	if err != nil {
		b.refuse(w, rec, ReasonBadRequest, err.Error())
		return
	}
	g, err := b.authorize(rec, host, port, MethodConnect, r.Header)
	if err == nil && g.Class == ClassPublicFetch {
		err = refused(ReasonPublicFetchProfile, "public-fetch grants do not permit CONNECT")
	}
	if err != nil {
		rf := asRefusal(err)
		b.refuse(w, rec, rf.reason, rf.detail)
		return
	}
	lim := b.opLimits(rec, g, host, port)
	deadline := b.o.Now().Add(lim.OperationTimeout)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	upstream, err := b.dialPinned(ctx, rec, g, host, port)
	if err != nil {
		rf := asRefusal(err)
		b.refuse(w, rec, rf.reason, rf.detail)
		return
	}
	defer upstream.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		b.refuse(w, rec, ReasonBadRequest, "connection cannot be hijacked")
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		b.finish(rec, ReasonBadRequest, err.Error())
		return
	}
	defer client.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		b.finish(rec, ReasonUpstream, err.Error())
		return
	}
	var src io.Reader = client
	if brw != nil && brw.Reader.Buffered() > 0 {
		src = io.MultiReader(io.LimitReader(brw.Reader, int64(brw.Reader.Buffered())), client)
	}
	src = bufio.NewReader(src)
	_ = client.SetReadDeadline(minTime(deadline, b.o.Now().Add(b.limits.DialTimeout)))
	sni, hello, err := readClientHello(client, src)
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		b.finish(rec, ReasonNotTLS, "the tunnel did not start with a TLS ClientHello")
		return
	}
	rec.SNI = sni
	if s, serr := canonicalHost(sni, false); sni != "" && (serr != nil || s != host) || sni == "" && !isIP(host) {
		b.finish(rec, ReasonSNIMismatch, "TLS server name "+sni+" does not match CONNECT host "+host)
		return
	}
	if err := b.authorized(rec); err != nil {
		b.finish(rec, ReasonEvidenceFailed, "evidence journal unavailable")
		return
	}
	sl := b.limiter(rec.Server)
	var upN, downN atomic.Int64
	upN.Add(int64(len(hello)))
	if int64(len(hello)) > lim.RequestBytes {
		b.finish(rec, ReasonRequestTooLarge, "ClientHello larger than the request limit")
		return
	}
	if _, err := upstream.Write(hello); err != nil {
		rec.BytesUp = upN.Load()
		b.finish(rec, ReasonUpstream, err.Error())
		return
	}
	upR := &meteredReader{r: src, limit: lim.RequestBytes, n: &upN, lim: sl.bytes, now: b.o.Now, tooLarge: ReasonRequestTooLarge}
	downR := &meteredReader{r: upstream, limit: lim.ResponseBytes, n: &downN, lim: sl.bytes, now: b.o.Now, tooLarge: ReasonResponseTooLarge}
	rf := splice(client, upstream, upR, downR, deadline)
	rec.BytesUp, rec.BytesDown = upN.Load(), downN.Load()
	if rf != nil {
		b.finish(rec, rf.reason, rf.detail)
		return
	}
	b.finish(rec, "", "")
}

// urlHost is the URL host of host:port, without the scheme's default
// port so that the Host header is the plain name.
func urlHost(host string, port, def int) string {
	if port == def {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return joinHostPort(host, port)
}

func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

func isIP(h string) bool { return strings.Contains(h, ":") || strings.Trim(h, "0123456789.") == "" }

func minTime(a, c time.Time) time.Time {
	if a.Before(c) {
		return a
	}
	return c
}
