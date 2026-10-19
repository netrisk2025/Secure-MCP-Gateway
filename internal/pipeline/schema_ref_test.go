package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A backend's input schema must not make the Gateway open local files: a
// $ref to a file:// URL or a relative name is refused, so the call fails
// closed with a schema finding instead of validating against the file.
func TestValidateArgumentsRefusesExternalRefs(t *testing.T) {
	dir := t.TempDir()
	// The referenced file accepts any number; if it were loaded, {"a": 5}
	// would pass validation.
	target := filepath.Join(dir, "allow.json")
	if err := os.WriteFile(target, []byte(`{"type":"number"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]string{
		"file url": "file://" + filepath.ToSlash(target),
		"relative": "allow.json",
		"https":    "https://example.invalid/schema.json",
	} {
		t.Run(name, func(t *testing.T) {
			schema := map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"$ref": ref}}}
			got := ValidateArguments(schema, []byte(`{"a":5}`))
			if got == "" {
				t.Fatalf("schema with $ref %q validated; the external reference was followed", ref)
			}
			if !strings.Contains(got, "does not compile") {
				t.Fatalf("finding = %q, want a compile refusal", got)
			}
		})
	}
}

// References inside the document and the draft meta-schemas still resolve.
func TestValidateArgumentsInternalRefs(t *testing.T) {
	schema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$defs":   map[string]any{"s": map[string]any{"type": "string"}},
		"type":    "object",
		"properties": map[string]any{
			"a": map[string]any{"$ref": "#/$defs/s"},
		},
	}
	if got := ValidateArguments(schema, []byte(`{"a":"x"}`)); got != "" {
		t.Fatalf("valid arguments refused: %s", got)
	}
	if got := ValidateArguments(schema, []byte(`{"a":1}`)); got == "" {
		t.Fatal("invalid arguments accepted")
	}
}
