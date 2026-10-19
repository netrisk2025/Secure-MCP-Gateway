package e2e

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// approveAll approves every request at once and records when the approval
// stage asked.
type approveAll struct {
	mu sync.Mutex
	at []time.Time
}

func (a *approveAll) Request(context.Context, pipeline.ApprovalRequest) (pipeline.ApprovalResult, error) {
	a.mu.Lock()
	a.at = append(a.at, time.Now())
	a.mu.Unlock()
	return pipeline.ApprovalResult{Outcome: pipeline.Approved, ApprovalID: "stage-order", Approver: "person"}, nil
}

// inspectFilter is an ordinary request filter of the inspection stage.
type inspectFilter struct{}

func (inspectFilter) ID() string { return "inspect-first" }

func (inspectFilter) FilterRequest(context.Context, *pipeline.Call, json.RawMessage) (pipeline.RequestVerdict, error) {
	return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
}

// TestStageOrder is FR-4.3's test: a call with an approval obligation,
// through a Gateway wired as cmd/smcpd wires the Observation Collector with
// synchronous scoring, is instrumented with the stage spans of FR-10.2 and
// the stages must be entered in the order authenticate, session check,
// decision, request inspection, request scoring, approval, launch
// authorization, dispatch, response validation, response inspection,
// response scoring and release authorization. Request scoring is the
// observe-request probe, which runs after every request inspection filter;
// response validation is the result size bound and the output-schema
// check that open the response chain; response scoring is the observe-response probe, which runs after
// every response inspection filter.
func TestStageOrder(t *testing.T) {
	reqtest.Verifies(t, "FR-4.3")
	var mu sync.Mutex
	var batches [][]pipeline.StageSpan
	ap := &approveAll{}
	of := startObservationOpts(t, "sampling_rate = 1.0\nflush_interval = \"20ms\"\nscoring = \"sync\"\n", func(f *pipeline.Filters) error {
		return f.RegisterRequest(inspectFilter{}, pipeline.Registration{Order: 500, Mandatory: true})
	}, func(sp []pipeline.StageSpan) {
		mu.Lock()
		batches = append(batches, append([]pipeline.StageSpan(nil), sp...))
		mu.Unlock()
	}, true, ap)
	access, _, _ := of.oauthLogin("smcp:template:ro")
	cs := of.mcpClient(access)
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "t_write", Arguments: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(batches)
		mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no span batch")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	spans := batches[0]
	mu.Unlock()
	ap.mu.Lock()
	asked := len(ap.at)
	ap.mu.Unlock()
	if asked != 1 {
		t.Fatalf("approval stage asked %d times", asked)
	}

	// Build the stage-entry sequence: stage spans by name, filter spans by
	// the stage they belong to (request scoring and response validation
	// and scoring are filter spans inside the inspection stages).
	stage := map[string]pipeline.StageSpan{}
	var reqFilters, respFilters []pipeline.StageSpan
	for _, s := range spans {
		if s.Stage != pipeline.SpanFilter {
			stage[s.Stage] = s
		}
	}
	reqInsp, respInsp := stage[pipeline.SpanRequestInspection], stage[pipeline.SpanResponseInspection]
	for _, s := range spans {
		if s.Stage != pipeline.SpanFilter {
			continue
		}
		switch {
		case !s.Start.Before(reqInsp.Start) && !s.End.After(reqInsp.End):
			reqFilters = append(reqFilters, s)
		case !s.Start.Before(respInsp.Start) && !s.End.After(respInsp.End):
			respFilters = append(respFilters, s)
		default:
			t.Fatalf("filter span %s outside the inspection stages", s.Filter)
		}
	}
	last := func(fs []pipeline.StageSpan, id string) pipeline.StageSpan {
		t.Helper()
		if len(fs) == 0 || fs[len(fs)-1].Filter != id {
			var ids []string
			for _, f := range fs {
				ids = append(ids, f.Filter)
			}
			t.Fatalf("%s is not the last filter of its stage: %v", id, ids)
		}
		for _, f := range fs[:len(fs)-1] {
			if f.End.After(fs[len(fs)-1].Start) {
				t.Fatalf("%s starts before %s ends", id, f.Filter)
			}
		}
		return fs[len(fs)-1]
	}
	first := func(fs []pipeline.StageSpan, id string) pipeline.StageSpan {
		t.Helper()
		for _, f := range fs {
			if f.Filter == id {
				return f
			}
		}
		t.Fatalf("no %s span", id)
		return pipeline.StageSpan{}
	}
	inspect := first(reqFilters, "inspect-first")
	reqScore := last(reqFilters, "observe-request")
	// Response validation is the size bound and the output-schema check;
	// every response inspection filter starts after both ended.
	validate := first(respFilters, "size-limit")
	schema := first(respFilters, "output-schema")
	respScore := last(respFilters, "observe-response")
	var respInspect pipeline.StageSpan
	for _, f := range respFilters {
		switch f.Filter {
		case "size-limit", "output-schema", "observe-response":
			continue
		}
		if f.Start.Before(validate.End) || f.Start.Before(schema.End) {
			t.Fatalf("response inspection filter %s starts before response validation ends", f.Filter)
		}
		if respInspect.Filter == "" {
			respInspect = f
		}
	}
	if respInspect.Filter == "" {
		t.Fatal("no response inspection filter span")
	}

	order := []struct {
		name string
		s    pipeline.StageSpan
	}{
		{"authenticate", stage[pipeline.SpanAuthenticate]},
		{"session check", stage[pipeline.SpanSessionCheck]},
		{"decision", stage[pipeline.SpanDecision]},
		{"request inspection", inspect},
		{"request scoring", reqScore},
		{"approval", stage[pipeline.SpanApproval]},
		{"launch authorization", stage[pipeline.SpanLaunchAuthorization]},
		{"dispatch", stage[pipeline.SpanDispatch]},
		{"response validation", validate},
		{"response inspection", respInspect},
		{"response scoring", respScore},
		{"release authorization", stage[pipeline.SpanReleaseAuthorization]},
	}
	for i, o := range order {
		if o.s.Start.IsZero() {
			t.Fatalf("no span for %s; spans %+v", o.name, spans)
		}
		if i > 0 && o.s.Start.Before(order[i-1].s.Start) {
			t.Fatalf("%s entered before %s", o.name, order[i-1].name)
		}
	}
	// The approval stage asked the Approver inside its span, after scoring.
	if ap.at[0].Before(reqScore.End) || ap.at[0].After(stage[pipeline.SpanLaunchAuthorization].Start) {
		t.Fatal("the Approver was asked outside the approval stage")
	}
}
