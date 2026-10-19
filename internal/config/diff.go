package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// arrayKeys names the identifying field of each array of tables, so that a
// change inside one entry is reported under that entry rather than as a
// change of the whole array.
var arrayKeys = map[string]string{"server": "alias", "client": "client_id", "principal": "id", "approver": "username"}

// Diff returns the dotted keys whose values differ between two validated
// configurations, sorted. Entries of [[server]], [[client]], [[principal]]
// and [[approver]] are keyed by their identifying field, for example
// "server.ref.command"; an added or removed entry is reported as its key
// ("client.<client_id>").
func Diff(a, b *Config) ([]string, error) {
	fa, err := flatten(a)
	if err != nil {
		return nil, err
	}
	fb, err := flatten(b)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for k, va := range fa {
		seen[k] = true
		if vb, ok := fb[k]; !ok || !reflect.DeepEqual(va, vb) {
			out = append(out, k)
		}
	}
	for k := range fb {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func flatten(c *Config) (map[string]any, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range doc {
		walk(out, k, k, v)
	}
	return out, nil
}

func walk(out map[string]any, top, prefix string, v any) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			out[prefix] = t
		}
		for k, sub := range t {
			walk(out, top, prefix+"."+k, sub)
		}
	case []any:
		id, keyed := arrayKeys[top]
		if !keyed || prefix != top {
			out[prefix] = t
			return
		}
		for i, e := range t {
			m, ok := e.(map[string]any)
			name := fmt.Sprint(i)
			if ok {
				if s, ok := m[id].(string); ok {
					name = s
				}
			}
			entry := prefix + "." + name
			out[entry] = true // presence of the entry itself
			if ok {
				for k, sub := range m {
					walk(out, top, entry+"."+k, sub)
				}
			}
		}
	default:
		out[prefix] = t
	}
}
