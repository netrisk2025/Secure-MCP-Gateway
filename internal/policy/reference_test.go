package policy

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestPolicyReferenceExamples is the documentation check of FR-18.5: every
// policy document example in docs/policy-reference.md compiles against the
// schema and the publication checks, and every field the schema defines is
// described there. TestPolicyReferenceCoversEveryObject checks the other
// object types, the predicate operators and the obligations.
func TestPolicyReferenceExamples(t *testing.T) {
	reqtest.Verifies(t, "FR-18.5")
	raw, err := os.ReadFile("../../docs/policy-reference.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	blocks := regexp.MustCompile("(?s)```json\n(.*?)```").FindAllStringSubmatch(doc, -1)
	n := 0
	for _, b := range blocks {
		if !strings.Contains(b[1], `"framework_profiles"`) {
			continue
		}
		n++
		if _, err := Compile([]byte(b[1])); err != nil {
			t.Errorf("example %d does not validate: %v", n, err)
		}
	}
	if n == 0 {
		t.Fatal("no policy document example found")
	}
	var schema any
	if err := json.Unmarshal(SchemaJSON(), &schema); err != nil {
		t.Fatal(err)
	}
	fields := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if props, ok := x["properties"].(map[string]any); ok {
				for k := range props {
					fields[k] = true
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(schema)
	var missing []string
	for f := range fields {
		if !strings.Contains(doc, "`"+f+"`") {
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("schema fields not described in docs/policy-reference.md: %v", missing)
	}
}
