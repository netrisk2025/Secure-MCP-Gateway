package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// depthOf is an independent depth count over the decoded document.
func depthOf(v any) int {
	switch x := v.(type) {
	case map[string]any:
		m := 0
		for _, e := range x {
			m = max(m, depthOf(e))
		}
		return m + 1
	case []any:
		m := 0
		for _, e := range x {
			m = max(m, depthOf(e))
		}
		return m + 1
	}
	return 0
}

// TestResultBoundsAtTheLimit is FR-4.10: the dispatcher buffers each
// response completely and passes it on only within the CP-08 limits. A
// result whose encoding is exactly the size limit is processed and one 1
// byte larger is rejected (ErrTooLarge, which the edge returns as -31003
// RESULT_TOO_LARGE, TestTimeoutCodesMatchAppendixB); a result nested
// exactly to the depth limit (32) is processed and one level deeper is
// rejected. The instance keeps serving.
func TestResultBoundsAtTheLimit(t *testing.T) {
	reqtest.Verifies(t, "FR-4.10")
	const limit = 16 << 10
	caps := pipeline.NewCapabilities(time.Minute)
	r := startRegistry(t, Limits{PerPrincipal: 2, Total: 2, Queue: 2, ResultBytes: limit}, caps)
	echo, deep := r.Resolve("m_echo"), r.Resolve("m_deep")
	empty, _ := json.Marshal(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: ""}}})
	n := limit - len(empty)
	for i, c := range []struct {
		size int
		ok   bool
	}{{n, true}, {n + 1, false}} {
		text := strings.Repeat("x", c.size)
		res, err := r.Call(context.Background(), dispatch(caps, echo, fmt.Sprintf("s%d", i), fmt.Sprintf(`{"text":%q}`, text)))
		if c.ok {
			raw, _ := json.Marshal(res)
			if err != nil || len(raw) != limit {
				t.Fatalf("result of exactly %d bytes: %d bytes, %v", limit, len(raw), err)
			}
		} else if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("result 1 byte over the limit: %v", err)
		}
	}
	// The result object is depth 1, structuredContent depth 2, and each
	// level adds one: 30 levels make 32.
	for i, c := range []struct {
		levels int
		ok     bool
	}{{30, true}, {31, false}} {
		res, err := r.Call(context.Background(), dispatch(caps, deep, fmt.Sprintf("d%d", i), fmt.Sprintf(`{"levels":%d}`, c.levels)))
		if c.ok {
			raw, _ := json.Marshal(res)
			var v any
			_ = json.Unmarshal(raw, &v)
			if err != nil || depthOf(v) != ResultDepth {
				t.Fatalf("result at depth %d: %v (depth %d)", ResultDepth, err, depthOf(v))
			}
		} else if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("result 1 level over the depth limit: %v", err)
		}
	}
	if _, err := r.Call(context.Background(), dispatch(caps, echo, "after", `{"text":"still here"}`)); err != nil {
		t.Fatal(err)
	}
}
