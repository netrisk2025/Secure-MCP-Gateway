package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// specDir is the MCP 2026-07-28 schema directory, relative to this
// package.
var specDir = filepath.Join("..", "..", "mcp-spec", "2026-07-28", "schema")

const schemaURL = "https://modelcontextprotocol.io/schema/2026-07-28/schema.json"

// example is one example file.
type example struct {
	Dir  string // the schema definition it illustrates
	Name string // file stem
	Raw  json.RawMessage
}

// examples maps each example directory to its files, sorted by name.
type examples map[string][]example

func loadExamples(t *testing.T) examples {
	t.Helper()
	root := filepath.Join(specDir, "examples")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	out := examples{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, err := filepath.Glob(filepath.Join(root, d.Name(), "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(files)
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			out[d.Name()] = append(out[d.Name()], example{Dir: d.Name(), Name: strings.TrimSuffix(filepath.Base(f), ".json"), Raw: raw})
		}
	}
	if len(out) == 0 {
		t.Fatal("no example directories")
	}
	return out
}

func (e examples) dirs() []string {
	var out []string
	for d := range e {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// one returns the single example of dir as a map.
func (e examples) one(t *testing.T, dir string) map[string]any {
	t.Helper()
	if len(e[dir]) == 0 {
		t.Fatalf("no example in %s", dir)
	}
	var m map[string]any
	if err := json.Unmarshal(e[dir][0].Raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// validator compiles schema.json definitions on demand.
type validator struct {
	mu   sync.Mutex
	c    *jsonschema.Compiler
	defs map[string]*jsonschema.Schema
}

func newValidator(t *testing.T) *validator {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specDir, "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaURL, doc); err != nil {
		t.Fatal(err)
	}
	return &validator{c: c, defs: map[string]*jsonschema.Schema{}}
}

// validate checks a JSON document against #/$defs/<def>.
func (v *validator) validate(def string, raw []byte) error {
	v.mu.Lock()
	s, ok := v.defs[def]
	if !ok {
		var err error
		if s, err = v.c.Compile(schemaURL + "#/$defs/" + def); err != nil {
			v.mu.Unlock()
			return fmt.Errorf("no schema definition %s: %w", def, err)
		}
		v.defs[def] = s
	}
	v.mu.Unlock()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return s.Validate(inst)
}

func (v *validator) validateValue(def string, x any) error {
	raw, err := json.Marshal(x)
	if err != nil {
		return err
	}
	return v.validate(def, raw)
}

// report collects one row per example directory.
type report struct {
	mu   sync.Mutex
	rows map[string][]string
}

func (r *report) add(dir, format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rows == nil {
		r.rows = map[string][]string{}
	}
	line := fmt.Sprintf(format, args...)
	for _, l := range r.rows[dir] {
		if l == line {
			return
		}
	}
	r.rows[dir] = append(r.rows[dir], line)
}

func (r *report) markdown(dirs []string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	b.WriteString("# MCP conformance suite report (FR-12.9)\n\n")
	b.WriteString("Examples: `mcp-spec/2026-07-28/schema/examples`. Schema: `mcp-spec/2026-07-28/schema/schema.json`. Produced by `go test ./internal/conformance`.\n\n")
	b.WriteString("| Example directory | Checks and outcome |\n|---|---|\n")
	for _, d := range dirs {
		b.WriteString("| `" + d + "` | " + strings.Join(r.rows[d], "; ") + " |\n")
	}
	return b.String()
}
