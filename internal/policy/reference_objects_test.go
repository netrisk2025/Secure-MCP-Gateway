package policy_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obspolicy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/research"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

// The FR-3.1 object types, the FR-3.12 obligation types and the SR-1.7-1
// operators the policy reference must describe.
var (
	referenceObjectTypes = []string{"Framework Profile", "Session Allow Policy Template", "Secret Use Policy", "Audit Profile",
		"Observation Policy", "Anomaly Response Policy", "Research Campaign"}
	referenceObligationTypes = []string{"Request filters, response filters", "Approval", "Rate limit", "Audit profile",
		"Observation policy", "Anomaly response", "Size limit", "Timeout", "Egress grants", "Secret grants", "Runtime profile"}
)

func readDoc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// section returns the text of the markdown section under heading (any
// level) up to the next heading of the same or a higher level.
func section(t *testing.T, doc, heading string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^(#+) ` + regexp.QuoteMeta(heading) + `\n`)
	m := re.FindStringSubmatchIndex(doc)
	if m == nil {
		t.Fatalf("no section %q", heading)
	}
	level := m[3] - m[2]
	rest := doc[m[1]:]
	end := regexp.MustCompile(`(?m)^#{1,` + fmt.Sprint(level) + `} `).FindStringIndex(rest)
	if end != nil {
		rest = rest[:end[0]]
	}
	return rest
}

func jsonExample(t *testing.T, text string) []byte {
	t.Helper()
	m := regexp.MustCompile("(?s)```json\n(.*?)```").FindStringSubmatch(text)
	if m == nil {
		t.Fatal("section has no JSON example")
	}
	return []byte(m[1])
}

// jsonFields returns every JSON field name of a struct type, nested
// structs, slices and maps included.
func jsonFields(t reflect.Type, out map[string]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || t.PkgPath() == "time" {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = true
		jsonFields(f.Type, out)
	}
}

func described(t *testing.T, text, what string, fields map[string]bool) {
	t.Helper()
	var missing []string
	for f := range fields {
		if !strings.Contains(text, "`"+f+"`") {
			missing = append(missing, f)
		}
	}
	slices.Sort(missing)
	if len(missing) > 0 {
		t.Errorf("%s: fields not described: %v", what, missing)
	}
}

func strictDecode(t *testing.T, raw []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("example %T: %v", v, err)
	}
}

// TestPolicyReferenceCoversEveryObject is the rest of FR-18.5's
// documentation check (TestPolicyReferenceExamples covers the policy
// document): the reference names every FR-3.1 object type and links to the
// description of its fields, describes every SR-1.7-1 predicate operator
// the schema allows and every FR-3.12 obligation of the decision record,
// and the example of each object outside the policy document passes the
// validation of the element that keeps it, with every field described.
func TestPolicyReferenceCoversEveryObject(t *testing.T) {
	reqtest.Verifies(t, "FR-18.5")
	doc := readDoc(t, "policy-reference.md")

	for _, ot := range referenceObjectTypes {
		if !strings.Contains(doc, "| "+ot+" |") {
			t.Errorf("object type %q not in the object table", ot)
		}
	}

	// Predicate operators: every op the schema accepts has a row.
	ops := regexp.MustCompile(`"op": \{ "type": "string", "enum": \[([^\]]*)\]`).FindSubmatch(policy.SchemaJSON())
	if ops == nil {
		t.Fatal("no op enum in the policy schema")
	}
	preds := section(t, doc, "Predicates")
	n := 0
	for _, op := range strings.Split(string(ops[1]), ",") {
		op = strings.Trim(strings.TrimSpace(op), `"`)
		n++
		if !strings.Contains(preds, "| `"+op+"` |") {
			t.Errorf("predicate operator %q not described", op)
		}
	}
	if n != 8 {
		t.Errorf("schema has %d operators, SR-1.7-1 names 8", n)
	}

	// Obligations: every FR-3.12 type and every decision-record field.
	obl := section(t, doc, "Obligations")
	for _, o := range referenceObligationTypes {
		if !strings.Contains(obl, "| "+o+" |") {
			t.Errorf("obligation type %q not described", o)
		}
	}
	fields := map[string]bool{}
	jsonFields(reflect.TypeOf(policy.Obligations{}), fields)
	described(t, obl, "obligations", fields)

	// Secret Use Policy: described in secrets.md; the example validates.
	sec := section(t, readDoc(t, "secrets.md"), "Secret Use Policy")
	var useSchema any
	if err := json.Unmarshal(secrets.UsePolicySchemaJSON(), &useSchema); err != nil {
		t.Fatal(err)
	}
	fields = map[string]bool{}
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
	walk(useSchema)
	described(t, sec, "Secret Use Policy", fields)
	servers := []config.Server{{Alias: "gh"}, {Alias: "db"}, {Alias: "sign"}, {Alias: "old", SecretEnv: map[string]string{"LEGACY_TOKEN": "legacy-token"}}}
	if _, err := secrets.CompileUsePolicy(jsonExample(t, sec), servers); err != nil {
		t.Errorf("Secret Use Policy example: %v", err)
	}

	// Observation objects: strict decode, every field described, and the
	// example passes the store's validation.
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf("[admin_listener]\naddress = \"127.0.0.1:0\"\n[state]\ndir = %q\n[policy]\nfile = %q\n"+
		"[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$x\"\n[observation]\nsampling_rate = 0.1\n", dir, filepath.Join(dir, "policy.json"))))
	if err != nil {
		t.Fatal(err)
	}
	store, err := obspolicy.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []struct {
		heading, kind string
		v             any
	}{
		{"Audit Profile", obspolicy.KindAuditProfile, &obspolicy.AuditProfile{}},
		{"Observation Policy", obspolicy.KindObservationPolicy, &obspolicy.ObservationPolicy{}},
		{"Anomaly Response Policy", obspolicy.KindAnomalyResponse, &obspolicy.AnomalyResponse{}},
	} {
		text := section(t, doc, o.heading)
		raw := jsonExample(t, text)
		strictDecode(t, raw, o.v)
		fields := map[string]bool{}
		jsonFields(reflect.TypeOf(o.v), fields)
		described(t, text, o.heading, fields)
		if err := store.Validate(o.kind, raw); err != nil {
			t.Errorf("%s example: %v", o.heading, err)
		}
	}

	// Research Campaign: the example creates a draft campaign.
	text := section(t, doc, "Research Campaign")
	raw := jsonExample(t, text)
	var spec research.Spec
	strictDecode(t, raw, &spec)
	fields = map[string]bool{}
	jsonFields(reflect.TypeOf(spec), fields)
	described(t, text, "Research Campaign", fields)
	cs, err := research.OpenCampaigns(filepath.Join(t.TempDir(), "c.json"), observe.DefaultCatalog(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Create(spec, "test"); err != nil {
		t.Errorf("Research Campaign example: %v", err)
	}
}
