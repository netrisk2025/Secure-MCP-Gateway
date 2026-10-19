package filters

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// typedSurface is a string argument whose schema or name marks it as a
// path or a URL.
type typedSurface struct {
	surface
	name string
}

// argKind decides whether a property is of the wanted kind from its name
// and schema.
type argKind struct {
	formats []string // JSON Schema "format" values
	smcp    string   // value of the "x-smcp-type" annotation
	names   []string // exact lower-case property names
	suffix  []string // lower-case name suffixes
}

func (k argKind) match(name string, sch map[string]any) bool {
	if sch != nil {
		if f, ok := sch["format"].(string); ok && slices.Contains(k.formats, strings.ToLower(f)) {
			return true
		}
		if t, ok := sch["x-smcp-type"].(string); ok {
			return strings.EqualFold(t, k.smcp)
		}
	}
	n := strings.ToLower(name)
	if slices.Contains(k.names, n) {
		return true
	}
	for _, s := range k.suffix {
		if strings.HasSuffix(n, s) && len(n) > len(s) {
			return true
		}
	}
	return false
}

var (
	pathKind = argKind{
		formats: []string{"path", "file-path", "filepath", "directory", "dir-path"},
		smcp:    "path",
		names:   []string{"path", "paths", "file", "files", "filename", "filepath", "file_path", "dir", "directory", "folder", "cwd", "root"},
		suffix:  []string{"_path", "path", "_paths", "paths", "_file", "_dir", "_directory", "_folder", "dir"},
	}
	urlKind = argKind{
		formats: []string{"uri", "url", "iri", "uri-reference", "iri-reference"},
		smcp:    "url",
		names:   []string{"url", "urls", "uri", "uris", "href", "link", "endpoint", "webhook", "callback", "redirect_uri"},
		suffix:  []string{"_url", "url", "_urls", "urls", "_uri", "uri", "_href", "_endpoint"},
	}
)

func withNames(k argKind, extra []string) argKind {
	if len(extra) == 0 {
		return k
	}
	k.names = slices.Clone(k.names)
	for _, n := range extra {
		k.names = append(k.names, strings.ToLower(n))
	}
	return k
}

func schemaMap(schema any) map[string]any {
	if m, ok := schema.(map[string]any); ok {
		return m
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// typedSurfaces walks the decoded arguments alongside the input schema and
// returns the string values of the wanted kind, at any nesting depth. A
// property without a schema is judged by its name alone; array items
// inherit the kind of their property.
func typedSurfaces(schema any, args any, k argKind) []typedSurface {
	var out []typedSurface
	var walk func(v any, sch map[string]any, ptr, name string, typed bool, set func(string))
	walk = func(v any, sch map[string]any, ptr, name string, typed bool, set func(string)) {
		switch t := v.(type) {
		case string:
			if typed && set != nil {
				s := t
				out = append(out, typedSurface{surface{loc: ptr, get: func() string { return s }, set: set}, name})
			}
		case map[string]any:
			props, _ := sch["properties"].(map[string]any)
			addl, _ := sch["additionalProperties"].(map[string]any)
			for _, key := range sortedKeys(t) {
				ps, _ := props[key].(map[string]any)
				if ps == nil {
					ps = addl
				}
				m, kk := t, key
				walk(t[key], ps, ptr+"/"+escapePtr(key), key, k.match(key, ps), func(s string) { m[kk] = s })
			}
		case []any:
			items, _ := sch["items"].(map[string]any)
			itemTyped := typed || (items != nil && k.match("", items))
			for i, e := range t {
				a, idx := t, i
				walk(e, items, ptr+"/"+strconv.Itoa(i), name, itemTyped, func(s string) { a[idx] = s })
			}
		}
	}
	walk(args, schemaMap(schema), "", "", false, nil)
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
