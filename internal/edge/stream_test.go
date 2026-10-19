package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestReasonMessages(t *testing.T) {
	// FR-1.51: the table is complete and substituted here; the -31001 and
	// -31002 wire forms are checked in internal/e2e. Not every code is
	// triggered end to end.
	reqtest.Partial(t, "FR-1.51")
	for reason, msg := range reasonMessages {
		if msg == "" || strings.Count(msg, ".") < 1 {
			t.Fatalf("%s: %q", reason, msg)
		}
	}
	url := "https://127.0.0.1:8444/approvals/a1"
	if m := Message(CodeApprovalRequired, "APPROVAL_REQUIRED", map[string]any{"approvalUrl": url}); m != "This call needs approval. Open "+url+" to approve it, then run the same request again." {
		t.Fatal(m)
	}
	if m := Message(CodeApprovalRequired, "APPROVAL_REQUIRED", nil); strings.Contains(m, "{approvalUrl}") {
		t.Fatal(m)
	}
	if m := Message(CodeResponseWithheld, "FILTER_BLOCKED", map[string]any{"correlationId": "c-9"}); !strings.Contains(m, "c-9") {
		t.Fatal(m)
	}
	if m := Message(CodeGatewayFailClosed, ReasonJournalUnavailable, nil); m != reasonMessages["JOURNAL_UNAVAILABLE"] {
		t.Fatal(m)
	}
	if m := Message(CodePolicyDenied, "SOME_FILTER_REASON", nil); m != codeMessages[CodePolicyDenied] {
		t.Fatal(m)
	}
	for code := range codeMessages {
		if Message(code, "UNKNOWN", nil) == "" {
			t.Fatalf("no fallback for %d", code)
		}
	}
	var data map[string]any
	_ = json.Unmarshal(gatewayError(CodePolicyDenied, "approval denied", ReasonApprovalDenied, "c", "d", nil).Data, &data)
	if data["message"] != "A person reviewing this call denied it." {
		t.Fatalf("%v", data)
	}
}

func TestHeldWriter(t *testing.T) {
	// Never held: one SSE event becomes the JSON body.
	rec := httptest.NewRecorder()
	hw := &heldWriter{w: rec, hdr: http.Header{}}
	hw.Header().Set("Content-Type", "text/event-stream")
	hw.Header().Set("Connection", "keep-alive")
	_, _ = hw.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"))
	hw.Flush()
	hw.comment("ignored before the stream starts")
	hw.finish()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" || rec.Body.String() != `{"jsonrpc":"2.0","id":1,"result":{}}` || rec.Header().Get("Connection") != "" {
		t.Fatalf("%q %q", ct, rec.Body.String())
	}
	if hw.startStream() {
		t.Fatal("stream started after finish")
	}

	// Held: the stream starts, buffered output is sent, then comments and
	// later events pass through.
	rec = httptest.NewRecorder()
	hw = &heldWriter{w: rec, hdr: http.Header{}}
	hw.Header().Set("Content-Type", "text/event-stream")
	_, _ = hw.Write([]byte("event: message\ndata: {\"n\":1}\n\n"))
	if !hw.startStream() {
		t.Fatal("stream did not start")
	}
	if !hw.startStream() {
		t.Fatal("stream did not start")
	}
	hw.comment("keep-alive\nwith newline")
	hw.WriteHeader(http.StatusTeapot) // ignored once streaming
	_, _ = hw.Write([]byte("event: message\ndata: {\"n\":2}\n\n"))
	hw.finish()
	want := "event: message\ndata: {\"n\":1}\n\n: keep-alive with newline\n\nevent: message\ndata: {\"n\":2}\n\n"
	if rec.Code != 200 || rec.Body.String() != want || rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}

	// An HTTP error is passed through unchanged and never streams.
	rec = httptest.NewRecorder()
	hw = &heldWriter{w: rec, hdr: http.Header{}}
	hw.Header().Set("Content-Type", "text/plain")
	hw.WriteHeader(http.StatusBadRequest)
	_, _ = hw.Write([]byte("bad request\n"))
	if hw.startStream() {
		t.Fatal("error response streamed")
	}
	hw.finish()
	if rec.Code != 400 || rec.Body.String() != "bad request\n" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}

	// Two events that were never held go out as an event stream.
	rec = httptest.NewRecorder()
	hw = &heldWriter{w: rec, hdr: http.Header{}}
	hw.Header().Set("Content-Type", "text/event-stream")
	_, _ = hw.Write([]byte("data: {\"a\":1}\n\ndata: {\"b\":2}\n\n"))
	hw.finish()
	if rec.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(rec.Body.String(), `{"b":2}`) {
		t.Fatalf("%q", rec.Body.String())
	}
	if d, ok := singleEventData([]byte("event: x\ndata: a\ndata: b\n\n")); !ok || string(d) != "a\nb" {
		t.Fatalf("%q %v", d, ok)
	}
}
