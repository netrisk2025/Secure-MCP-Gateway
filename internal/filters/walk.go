package filters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// surface is one string reachable by the harness: a location (JSON pointer
// into the arguments or the result) with accessors.
type surface struct {
	loc string
	get func() string
	set func(string)
}

func escapePtr(k string) string {
	return strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
}

// decodeJSON decodes raw into generic values, keeping numbers exact.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return v, nil
}

// valueSurfaces lists every string value inside v (maps and slices are
// walked in place, so set modifies v). root replaces v itself when v is a
// string.
func valueSurfaces(v any, ptr string, root func(string)) []surface {
	var out []surface
	var walk func(v any, ptr string, set func(string))
	walk = func(v any, ptr string, set func(string)) {
		switch t := v.(type) {
		case string:
			s := t
			out = append(out, surface{loc: ptr, get: func() string { return s }, set: set})
		case map[string]any:
			// Sorted keys: a clone of the value lists its surfaces in the
			// same order, so indexes carry over.
			for _, k := range slices.Sorted(maps.Keys(t)) {
				m, key := t, k
				walk(t[k], ptr+"/"+escapePtr(k), func(s string) { m[key] = s })
			}
		case []any:
			for i, e := range t {
				a, idx := t, i
				walk(e, ptr+"/"+strconv.Itoa(i), func(s string) { a[idx] = s })
			}
		}
	}
	walk(v, ptr, root)
	return out
}

// resultSurfaces lists the text surfaces of a result that reach the
// harness (SR-5.9-1): text content, embedded resource text and URIs,
// resource-link URIs and labels, structured content and backend _meta.
// Binary data (image, audio, blobs) is the content-type gate's concern.
func resultSurfaces(res *mcp.CallToolResult) []surface {
	var out []surface
	add := func(loc string, p *string) {
		if *p != "" {
			out = append(out, surface{loc: loc, get: func() string { return *p }, set: func(s string) { *p = s }})
		}
	}
	for i, c := range res.Content {
		base := "/content/" + strconv.Itoa(i)
		switch t := c.(type) {
		case *mcp.TextContent:
			add(base+"/text", &t.Text)
		case *mcp.ResourceLink:
			add(base+"/uri", &t.URI)
			add(base+"/name", &t.Name)
			add(base+"/title", &t.Title)
			add(base+"/description", &t.Description)
		case *mcp.EmbeddedResource:
			if t.Resource != nil {
				add(base+"/resource/uri", &t.Resource.URI)
				add(base+"/resource/text", &t.Resource.Text)
			}
		}
	}
	if res.StructuredContent != nil {
		r := res
		out = append(out, valueSurfaces(res.StructuredContent, "/structuredContent", func(s string) { r.StructuredContent = s })...)
	}
	if res.Meta != nil {
		out = append(out, valueSurfaces(map[string]any(res.Meta), "/_meta", nil)...)
	}
	return out
}

// cloneResult deep-copies a result through its wire form so that a
// transforming filter never changes the input of a later or failed stage.
func cloneResult(res *mcp.CallToolResult) (*mcp.CallToolResult, error) {
	raw, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	var out mcp.CallToolResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if res.StructuredContent != nil {
		// Decode structured content generically with exact numbers.
		sraw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			return nil, err
		}
		if out.StructuredContent, err = decodeJSON(sraw); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// argSurfaces decodes arguments and lists their string values. ok is
// false when the arguments are not valid JSON.
func argSurfaces(args json.RawMessage) (any, []surface, bool) {
	if len(bytes.TrimSpace(args)) == 0 {
		return map[string]any{}, nil, true
	}
	v, err := decodeJSON(args)
	if err != nil {
		return nil, nil, false
	}
	// MCP arguments are an object; a bare string has no settable parent.
	return v, valueSurfaces(v, "", nil), true
}

// depth returns the nesting depth of a generic JSON value (a scalar is 0).
func depth(v any) int {
	switch t := v.(type) {
	case map[string]any:
		m := 0
		for _, e := range t {
			m = max(m, depth(e))
		}
		return m + 1
	case []any:
		m := 0
		for _, e := range t {
			m = max(m, depth(e))
		}
		return m + 1
	}
	return 0
}
