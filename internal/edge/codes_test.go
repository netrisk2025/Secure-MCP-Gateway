package edge

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestTimeoutCodesMatchAppendixB: SRS Appendix B gives UPSTREAM_TIMEOUT
// (the backend did not answer and may have acted) -31009 and
// CLIENT_DEADLINE -31008; an InputRequiredResult without the MRTR Relay
// Profile is -31010 INPUT_REQUIRED_UNSUPPORTED.
func TestTimeoutCodesMatchAppendixB(t *testing.T) {
	reqtest.Partial(t, "FR-1.51", "FR-5.24")
	h := newHarness(t, harnessOpts{})
	s, _ := h.session("ro")
	for _, tc := range []struct {
		err    error
		code   int64
		reason string
		phase  audit.Phase
	}{
		{backend.ErrTimeout, CodeIndeterminate, "UPSTREAM_TIMEOUT", audit.PhaseIndeterminate},
		{context.DeadlineExceeded, CodeTimeout, "CLIENT_DEADLINE", audit.PhaseIndeterminate},
		{backend.ErrInputRequired, CodeInputRequired, "INPUT_REQUIRED_UNSUPPORTED", audit.PhaseFailed}, // FR-5.24
	} {
		corr := "corr-" + tc.reason
		c := &callRun{g: h.gw, corr: corr, base: audit.Event{CorrelationID: corr}, dec: policy.Decision{ID: "d", PolicyRevision: "r1"}}
		var we *jsonrpc.Error
		if err := h.gw.mapDispatchError(c, s.ID, tc.err); !errors.As(err, &we) || we.Code != tc.code {
			t.Fatalf("%s: %v", tc.reason, err)
		}
		var data map[string]any
		if err := json.Unmarshal(we.Data, &data); err != nil || data["reasonCode"] != tc.reason || data["message"] != Message(tc.code, tc.reason, data) {
			t.Fatalf("%s: data %s %v", tc.reason, we.Data, err)
		}
		e := h.rec.find(func(e audit.Event) bool { return e.CorrelationID == corr })
		if e == nil || e.Phase != tc.phase || e.ReasonCode != tc.reason {
			t.Fatalf("%s: event %+v", tc.reason, e)
		}
	}
}
