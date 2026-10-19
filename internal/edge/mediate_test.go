package edge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestListenKeepAlive is FR-1.36: an idle listen stream gets an SSE
// comment line each keep-alive interval, which is CP-20's 15 s by
// default. The test shortens the interval.
func TestListenKeepAlive(t *testing.T) {
	reqtest.Verifies(t, "FR-1.36")
	if listenKeepAlive != 15*time.Second {
		t.Fatalf("CP-20 keep-alive interval is %s", listenKeepAlive)
	}
	h := newHarness(t, harnessOpts{})
	if h.gw.listenInterval != listenKeepAlive {
		t.Fatalf("gateway keep-alive interval %s", h.gw.listenInterval)
	}
	const interval = 150 * time.Millisecond
	h.gw.listenInterval = interval
	_, tok := h.session("ro")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", h.srv.URL+"/mcp", strings.NewReader(
		fmt.Sprintf(`{"jsonrpc":"2.0","id":"K","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{%s}}}`, wireMeta)))
	for k, v := range wireHeaders(tok, "subscriptions/listen") {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("headers %v", resp.Header)
	}
	sc := bufio.NewScanner(resp.Body)
	var ack time.Time
	var comments []time.Time
	for len(comments) < 4 && sc.Scan() {
		line := sc.Text()
		switch {
		case strings.Contains(line, "acknowledged"):
			ack = time.Now()
		case strings.HasPrefix(line, ":"):
			if ack.IsZero() {
				t.Fatal("keep-alive before the acknowledgement")
			}
			comments = append(comments, time.Now())
		}
	}
	if len(comments) < 4 {
		t.Fatalf("got %d keep-alives: %v", len(comments), sc.Err())
	}
	prev := ack
	for i, c := range comments {
		gap := c.Sub(prev)
		if gap < interval-30*time.Millisecond || gap > 3*interval {
			t.Fatalf("keep-alive %d after %s, interval %s", i, gap, interval)
		}
		prev = c
	}
}

// TestListenWriterKeepAliveOnlyWhenIdle: a stream that carried an event
// within the interval gets no keep-alive until it has been idle for a
// full interval.
func TestListenWriterKeepAliveOnlyWhenIdle(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "text/event-stream")
	lw := newListenWriter(rec, 100*time.Millisecond)
	lw.WriteHeader(200)
	for i := 0; i < 6; i++ { // an event every 40 ms keeps the stream busy
		time.Sleep(40 * time.Millisecond)
		_, _ = lw.Write([]byte("data: {}\n\n"))
	}
	lw.mu.Lock()
	busy := strings.Contains(rec.Body.String(), ": keep-alive")
	lw.mu.Unlock()
	if busy {
		t.Fatalf("keep-alive on a busy stream: %q", rec.Body.String())
	}
	time.Sleep(250 * time.Millisecond)
	lw.finish([]byte(`"x"`), false)
	if !strings.Contains(rec.Body.String(), ": keep-alive") {
		t.Fatalf("no keep-alive on an idle stream: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "complete") {
		t.Fatal("complete response on a stream the client ended")
	}
}

// TestReleaseCommitFailureWithholds is SR-6.3-1: when the outcome cannot
// be committed after the backend responded, the result is withheld with
// -31003 and none of its content reaches the harness.
func TestReleaseCommitFailureWithholds(t *testing.T) {
	reqtest.Verifies(t, "SR-6.3-1")
	reqtest.Scenario(t, reqtest.Standalone, "AT-12") // journal flush fault before release
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	h.rec.set(func(ev audit.Event) error {
		if ev.Phase == audit.PhaseDelivered {
			return errors.New("fsync failed")
		}
		return nil
	}, nil)
	hdr := wireHeaders(tok, "tools/call")
	hdr["Mcp-Name"] = "t_echo"
	status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"secret-result-text"},"_meta":{%s}}}`, wireMeta), hdr)
	r := decodeReply(t, body)
	if status != 200 || r.Error == nil || r.Error.Code.String() != fmt.Sprint(CodeResponseWithheld) || !strings.Contains(body, ReasonOutcomeUnrecorded) {
		t.Fatalf("%d %s", status, body)
	}
	if h.rec.find(func(e audit.Event) bool { return e.Phase == audit.PhaseCompleted }) == nil {
		t.Fatal("the backend never responded; the test did not reach release")
	}
	if strings.Contains(body, "echo:") {
		t.Fatalf("released content reached the harness: %s", body)
	}
}

// TestIntentCommitFailureJournalUnavailable is SR-1.2-2 in part: a failed
// commit of the decision intent refuses launch with -31004 and
// JOURNAL_UNAVAILABLE, and nothing is dispatched.
//
// The unwritable journal directory and the graph database outage during
// traffic are run against the real journal by
// e2e.TestJournalUnwritableDuringTraffic.
func TestIntentCommitFailureJournalUnavailable(t *testing.T) {
	reqtest.Partial(t, "SR-1.2-2")
	h := newHarness(t, harnessOpts{})
	_, tok := h.session("ro")
	h.rec.set(func(ev audit.Event) error {
		if ev.Phase == audit.PhaseAuthorized {
			return errors.New("fsync failed")
		}
		return nil
	}, nil)
	hdr := wireHeaders(tok, "tools/call")
	hdr["Mcp-Name"] = "t_echo"
	status, _, body := h.post(fmt.Sprintf(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"x"},"_meta":{%s}}}`, wireMeta), hdr)
	r := decodeReply(t, body)
	if status != 200 || r.Error == nil || r.Error.Code.String() != fmt.Sprint(CodeGatewayFailClosed) || !strings.Contains(body, `"reasonCode":"JOURNAL_UNAVAILABLE"`) {
		t.Fatalf("%d %s", status, body)
	}
	if h.rec.find(func(e audit.Event) bool { return e.Phase == audit.PhaseDispatched }) != nil || h.caps.Outstanding() != 0 {
		t.Fatal("the call was dispatched without a committed intent")
	}
}
