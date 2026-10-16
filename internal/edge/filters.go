package edge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaCache compiles each backend input schema once.
var schemaCache sync.Map // string(schema JSON) -> *jsonschema.Schema

// validateArguments is the schema-validate request filter (FR-4.5). It
// returns an empty string when the arguments conform, otherwise a finding.
// Validation is bounded by the schema itself (CP-36 limits are not yet
// enforced in this slice).
func validateArguments(schema any, args json.RawMessage) string {
	raw, err := json.Marshal(schema)
	if err != nil {
		return "schema not serializable"
	}
	key := string(raw)
	var compiled *jsonschema.Schema
	if v, ok := schemaCache.Load(key); ok {
		compiled = v.(*jsonschema.Schema)
	} else {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return "schema not parseable"
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource("tool.json", doc); err != nil {
			return "schema not loadable"
		}
		compiled, err = c.Compile("tool.json")
		if err != nil {
			return "schema does not compile: " + err.Error()
		}
		schemaCache.Store(key, compiled)
	}
	var inst any = map[string]any{}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &inst); err != nil {
			return "arguments are not valid JSON"
		}
	}
	if err := compiled.Validate(inst); err != nil {
		msg := err.Error()
		if i := strings.Index(msg, "\n"); i > 0 {
			msg = msg[:i]
		}
		return fmt.Sprintf("%s", msg)
	}
	return ""
}
