package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func validateCall(schema string, args string) RequestVerdict {
	var s any
	if err := json.Unmarshal([]byte(schema), &s); err != nil {
		panic(err)
	}
	v, _ := SchemaValidate{}.FilterRequest(context.Background(), &Call{InputSchema: s}, json.RawMessage(args))
	return v
}

// TestSchemaDialects is SR-1.8-2: the schema-validate request filter
// validates arguments against JSON Schema 2020-12 and draft-07 schemas
// (with and without $schema), treats any other dialect as a validation
// failure that blocks the call, and does not dereference an https $ref:
// the call is blocked and the referenced server sees no request.
func TestSchemaDialects(t *testing.T) {
	reqtest.Verifies(t, "SR-1.8-2")
	body := `"type": "object", "properties": {"n": {"type": "integer", "maximum": 10}}, "required": ["n"]`
	for _, dialect := range []string{"", `"$schema": "https://json-schema.org/draft/2020-12/schema",`,
		`"$schema": "http://json-schema.org/draft-07/schema#",`, `"$schema": "http://json-schema.org/draft-07/schema",`} {
		schema := "{" + dialect + body + "}"
		if v := validateCall(schema, `{"n": 3}`); v.Action != Pass {
			t.Errorf("%s: valid arguments blocked: %+v", dialect, v)
		}
		if v := validateCall(schema, `{"n": 11}`); v.Action != Block || v.ReasonCode != ReasonSchemaInvalid {
			t.Errorf("%s: invalid arguments passed: %+v", dialect, v)
		}
	}
	// Other dialects, at the root or nested, are a validation failure.
	for _, other := range []string{
		`{"$schema": "http://json-schema.org/draft-04/schema#",` + body + `}`,
		`{"$schema": "https://json-schema.org/draft/2019-09/schema",` + body + `}`,
		`{"$schema": 7,` + body + `}`,
		`{"type": "object", "properties": {"n": {"$schema": "http://json-schema.org/draft-06/schema#", "type": "integer"}}}`,
	} {
		if v := validateCall(other, `{"n": 3}`); v.Action != Block || v.ReasonCode != ReasonSchemaInvalid || !strings.Contains(v.Finding, "dialect") {
			t.Errorf("%s: %+v", other, v)
		}
	}
	// An https reference is never fetched.
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"type": "integer"}`))
	}))
	defer srv.Close()
	remote := fmt.Sprintf(`{"type": "object", "properties": {"n": {"$ref": %q}}}`, srv.URL+"/n.json")
	if v := validateCall(remote, `{"n": 3}`); v.Action != Block {
		t.Fatalf("remote $ref: %+v", v)
	}
	time.Sleep(50 * time.Millisecond)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the referenced server saw %d requests", n)
	}
}

// TestSchemaResourceBounds is SR-1.8-3: validation is aborted and the call
// blocked when the schema exceeds the CP-36 depth (32) or subschema count
// (1,000), or when validation runs past the CP-36 time bound (50 ms): an
// exponential composition schema (each level an anyOf of two references
// to the next, the instance failing every branch) is aborted within the
// bound rather than evaluated to the end.
func TestSchemaResourceBounds(t *testing.T) {
	reqtest.Verifies(t, "SR-1.8-3")
	nest := func(levels int) string {
		s := `{"type": "integer"}`
		for range levels {
			s = `{"type": "object", "properties": {"x": ` + s + `}}`
		}
		return s
	}
	if v := validateCall(nest(14), `{}`); v.Action != Pass { // 29 levels of JSON nesting
		t.Fatalf("schema within the depth bound blocked: %+v", v)
	}
	if v := validateCall(nest(17), `{}`); v.Action != Block || !strings.Contains(v.Finding, "deeper") {
		t.Fatalf("deep schema: %+v", v)
	}
	var props []string
	for i := range 1001 {
		props = append(props, fmt.Sprintf(`"p%d": {"type": "string"}`, i))
	}
	wide := `{"type": "object", "properties": {` + strings.Join(props, ",") + `}}`
	if v := validateCall(wide, `{}`); v.Action != Block || !strings.Contains(v.Finding, "subschemas") {
		t.Fatalf("wide schema: %+v", v)
	}
	// Exponential composition: 2^20 branch evaluations without the bound.
	const levels = 20
	defs := []string{fmt.Sprintf(`"d%d": {"type": "string"}`, levels)}
	for i := range levels {
		defs = append(defs, fmt.Sprintf(`"d%d": {"anyOf": [{"$ref": "#/$defs/d%d"}, {"$ref": "#/$defs/d%d"}]}`, i, i+1, i+1))
	}
	expo := `{"$defs": {` + strings.Join(defs, ",") + `}, "type": "object", "properties": {"v": {"$ref": "#/$defs/d0"}}}`
	start := time.Now()
	v := validateCall(expo, `{"v": 1}`)
	took := time.Since(start)
	if v.Action != Block || !strings.Contains(v.Finding, "exceeded") {
		t.Fatalf("exponential schema: %+v after %v", v, took)
	}
	// Compilation is outside the bound; the abort itself follows it closely.
	if took > SchemaValidateTime+2*time.Second {
		t.Fatalf("aborted after %v", took)
	}
}

// TestSchemaBoundStartsWithValidation: the CP-36 time bound counts the
// validation, not the wait for the validator goroutine to be scheduled, so
// a conforming call on a busy host is not blocked.
func TestSchemaBoundStartsWithValidation(t *testing.T) {
	hook := func() { time.Sleep(2 * SchemaValidateTime) }
	validatorStartHook.Store(&hook)
	defer validatorStartHook.Store(nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}, "required": []any{"path"}}
	if f := ValidateArguments(schema, json.RawMessage(`{"path":"64k.txt"}`)); f != "" {
		t.Fatalf("conforming arguments blocked: %s", f)
	}
	if f := ValidateArguments(schema, json.RawMessage(`{"path":1}`)); f == "" || strings.Contains(f, "exceeded") {
		t.Fatalf("non-conforming arguments: %q", f)
	}
	ctx, cancel := context.WithTimeout(context.Background(), SchemaValidateTime/2)
	defer cancel()
	if f := ValidateArgumentsContext(ctx, schema, json.RawMessage(`{"path":"x"}`)); !strings.Contains(f, "did not start") {
		t.Fatalf("validator not started before the deadline: %q", f)
	}
}
