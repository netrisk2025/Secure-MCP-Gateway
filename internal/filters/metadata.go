package filters

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Schema bounds applied at import (CP-36, SR-1.8-2, SR-1.8-3; Appendix L
// HF-10 to HF-12).
const (
	SchemaMaxDepth      = 32
	SchemaMaxSubschemas = 1000
	SchemaMaxEnum       = 1000
	ruleSetSchema       = "schema-bounds"
	ruleSetShadowing    = "cross-server-shadowing"
)

var allowedDialects = []string{
	"https://json-schema.org/draft/2020-12/schema",
	"http://json-schema.org/draft-07/schema#",
	"http://json-schema.org/draft-07/schema",
}

// metaText is one presented metadata string of a tool.
type metaText struct{ loc, text string }

// toolTexts lists every presented string of a tool: name, title,
// description, annotation title and, at any depth of the input and output
// schemas, every title, description, enum, const, default and examples
// string.
func toolTexts(t *mcp.Tool) []metaText {
	out := []metaText{{"/name", t.Name}, {"/title", t.Title}, {"/description", t.Description}}
	if t.Annotations != nil {
		out = append(out, metaText{"/annotations/title", t.Annotations.Title})
	}
	for _, sc := range []struct {
		loc string
		v   any
	}{{"/inputSchema", t.InputSchema}, {"/outputSchema", t.OutputSchema}} {
		if sc.v == nil {
			continue
		}
		raw, err := json.Marshal(sc.v)
		if err != nil {
			continue
		}
		v, err := decodeJSON(raw)
		if err != nil {
			continue
		}
		var walk func(v any, ptr, key string)
		walk = func(v any, ptr, key string) {
			switch x := v.(type) {
			case string:
				switch key {
				case "title", "description", "enum", "const", "default", "examples", "$comment":
					out = append(out, metaText{ptr, x})
				}
			case map[string]any:
				for _, k := range sortedKeys(x) {
					walk(x[k], ptr+"/"+escapePtr(k), k)
				}
			case []any:
				for i, e := range x {
					walk(e, ptr+"/"+strconv.Itoa(i), key) // enum and examples items keep their key
				}
			}
		}
		walk(v, sc.loc, "")
	}
	return slices.DeleteFunc(out, func(m metaText) bool { return m.text == "" })
}

func schemaBounds(t *mcp.Tool) []pipeline.Finding {
	var out []pipeline.Finding
	add := func(rule, loc string) {
		out = append(out, pipeline.Finding{Filter: "metadata-scan", RuleSet: ruleSetSchema, RuleSetVersion: filterVersion, Rule: rule, Location: loc})
	}
	for _, sc := range []struct {
		loc string
		v   any
	}{{"/inputSchema", t.InputSchema}, {"/outputSchema", t.OutputSchema}} {
		if sc.v == nil {
			continue
		}
		raw, err := json.Marshal(sc.v)
		if err != nil {
			add("unserializable", sc.loc)
			continue
		}
		v, err := decodeJSON(raw)
		if err != nil {
			add("unserializable", sc.loc)
			continue
		}
		if d := depth(v); d > SchemaMaxDepth {
			add("depth", sc.loc)
		}
		count := 0
		var walk func(v any, ptr string)
		walk = func(v any, ptr string) {
			switch x := v.(type) {
			case map[string]any:
				count++
				if ref, ok := x["$ref"].(string); ok && !strings.HasPrefix(ref, "#") {
					add("remote-ref", ptr+"/$ref")
				}
				if d, ok := x["$schema"].(string); ok && !slices.Contains(allowedDialects, d) {
					add("dialect", ptr+"/$schema")
				}
				if e, ok := x["enum"].([]any); ok && len(e) > SchemaMaxEnum {
					add("enum-size", ptr+"/enum")
				}
				for _, k := range sortedKeys(x) {
					walk(x[k], ptr+"/"+escapePtr(k))
				}
			case []any:
				for i, e := range x {
					walk(e, ptr+"/"+strconv.Itoa(i))
				}
			}
		}
		walk(v, sc.loc)
		if count > SchemaMaxSubschemas {
			add("subschema-count", sc.loc)
		}
	}
	return out
}

// shadowing reports metadata of tool t of server that names a tool of
// another server: its public name, or a distinctive backend tool name
// (containing "_", "-" or "." and at least 5 characters) that server itself
// does not also provide (Appendix L HF-15).
func shadowing(server string, t *mcp.Tool, own []string, others map[string][]string) []pipeline.Finding {
	var out []pipeline.Finding
	texts := toolTexts(t)
	for _, alias := range sortedAliases(others) {
		if alias == server {
			continue
		}
		for _, name := range others[alias] {
			needles := []string{strings.ToLower(backend.PublicName(alias, name))}
			if len(name) >= 5 && strings.ContainsAny(name, "_-.") && !slices.Contains(own, name) {
				needles = append(needles, strings.ToLower(name))
			}
			for _, mt := range texts {
				if mt.loc == "/name" {
					continue
				}
				low := strings.ToLower(mt.text)
				for _, n := range needles {
					if containsWord(low, n) {
						out = append(out, pipeline.Finding{Filter: "metadata-scan", RuleSet: ruleSetShadowing, RuleSetVersion: filterVersion,
							Rule: "names-other-server-tool", Location: mt.loc})
						break
					}
				}
			}
		}
	}
	return out
}

func sortedAliases(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func wordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_'
}

func containsWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(w)
		if (j == 0 || !wordByte(s[j-1])) && (end == len(s) || !wordByte(s[end])) {
			return true
		}
		i = j + 1
	}
}

// ScanTool applies the active metadata, unicode-control, schema-bounds and
// shadowing rules to one tool. Every returned finding blocks presentation
// except tag findings of the metadata rule set.
func (in *Inspector) ScanTool(server string, t *mcp.Tool, own []string, others map[string][]string) []pipeline.Finding {
	md, uc := in.ruleSet(RuleSetMetadata), in.ruleSet(RuleSetUnicode)
	var out []pipeline.Finding
	for _, mt := range toolTexts(t) {
		for _, m := range uc.Scan(mt.text) {
			out = append(out, finding("metadata-scan", uc, m.Rule, mt.loc, false))
		}
		for _, m := range md.Scan(mt.text) {
			out = append(out, finding("metadata-scan", md, m.Rule, mt.loc, m.Rule.RequestAction == ActionTag))
		}
	}
	out = append(out, schemaBounds(t)...)
	out = append(out, shadowing(server, t, own, others)...)
	if len(out) > maxFindings {
		out = out[:maxFindings]
	}
	return out
}

func blocking(fs []pipeline.Finding) bool {
	return slices.ContainsFunc(fs, func(f pipeline.Finding) bool { return !f.Tag })
}

// SuspendedTool is a tool withheld from every catalog by the metadata scan.
type SuspendedTool struct {
	Server         string             `json:"server"`
	ServerRevision string             `json:"serverRevision"`
	Tool           string             `json:"tool"`
	Stage          string             `json:"stage"` // "import" or "presentation"
	Findings       []pipeline.Finding `json:"findings"`
}

// metadataState tracks imported tool names and suspensions.
type metadataState struct {
	mu        sync.Mutex
	imported  map[string][]string // alias -> backend tool names (all, including suspended)
	suspended map[string]SuspendedTool
	reported  map[string]bool // presentation findings already recorded
}

func suspendKey(server, rev, tool string) string { return server + "\x00" + rev + "\x00" + tool }

func (in *Inspector) recordBlocked(ctx context.Context, stage, origin string, st SuspendedTool) {
	_ = ctx
	ev := audit.Event{Class: "server", Origin: origin, Outcome: "metadata_blocked", ReasonCode: ReasonMetadataBlocked,
		ServerRevision: st.ServerRevision, ToolRevision: st.ServerRevision + "/" + st.Tool, PolicyStatus: "not_evaluated",
		Detail: map[string]any{"server": st.Server, "tool": st.Tool, "stage": stage, "findings": st.Findings}}
	if in.evidence == nil {
		return
	}
	if err := in.evidence.Commit(ev); err != nil {
		in.log.Error("evidence write failed for metadata_blocked", "err", err, "server", st.Server, "tool", st.Tool)
	}
}

// Suspended lists the tools the metadata scan withheld, at import and at
// presentation.
func (in *Inspector) Suspended() []SuspendedTool {
	in.meta.mu.Lock()
	defer in.meta.mu.Unlock()
	out := make([]SuspendedTool, 0, len(in.meta.suspended))
	for _, s := range in.meta.suspended {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b SuspendedTool) int {
		return strings.Compare(a.Server+"/"+a.Tool, b.Server+"/"+b.Tool)
	})
	return out
}

func (in *Inspector) otherNames() map[string][]string {
	names := map[string][]string{}
	in.meta.mu.Lock()
	for k, v := range in.meta.imported {
		names[k] = slices.Clone(v)
	}
	in.meta.mu.Unlock()
	if in.names != nil {
		for k, v := range in.names() {
			names[k] = v
		}
	}
	return names
}

// scanningManifest applies the metadata scan when a server revision is
// imported (SR-5.9-2): tools with a blocking finding are left out of the
// tool set, so they are never registered, presented or callable, and a
// metadata_blocked event names the rules and rule-set versions.
type scanningManifest struct {
	inner pipeline.ManifestSource
	in    *Inspector
}

// Manifests wraps a ManifestSource with the import-time metadata scan. A
// nil inner source means the live tool list.
func (in *Inspector) Manifests(inner pipeline.ManifestSource) pipeline.ManifestSource {
	if inner == nil {
		inner = pipeline.LiveManifest{}
	}
	if !in.metadataScan {
		return inner
	}
	return scanningManifest{inner: inner, in: in}
}

func (m scanningManifest) Tools(ctx context.Context, spec pipeline.ServerSpec, live pipeline.LiveLister) (pipeline.ToolSet, error) {
	ts, err := m.inner.Tools(ctx, spec, live)
	if err != nil {
		return ts, err
	}
	own := make([]string, 0, len(ts.Tools))
	for _, t := range ts.Tools {
		own = append(own, t.Name)
	}
	others := m.in.otherNames()
	kept := ts.Tools[:0:0]
	for _, t := range ts.Tools {
		fs := m.in.ScanTool(spec.Alias, t, own, others)
		if !blocking(fs) {
			kept = append(kept, t)
			continue
		}
		st := SuspendedTool{Server: spec.Alias, ServerRevision: ts.Revision, Tool: t.Name, Stage: "import", Findings: fs}
		m.in.meta.mu.Lock()
		m.in.meta.suspended[suspendKey(spec.Alias, ts.Revision, t.Name)] = st
		m.in.meta.mu.Unlock()
		m.in.log.Warn("tool suspended by the metadata scan", "server", spec.Alias, "tool", t.Name, "findings", len(fs))
		m.in.recordBlocked(ctx, "import", "E-14", st)
		ts.Withheld = append(ts.Withheld, pipeline.WithheldTool{Name: t.Name, ReasonCode: ReasonMetadataBlocked, Stage: "import", Findings: fs})
	}
	m.in.meta.mu.Lock()
	m.in.meta.imported[spec.Alias] = own
	m.in.meta.mu.Unlock()
	ts.Tools = kept
	return ts, nil
}

// ListChanged forwards notifications/tools/list_changed to the wrapped
// source when it watches them (signed packages: drift suspends the server).
func (m scanningManifest) ListChanged(ctx context.Context, spec pipeline.ServerSpec, live pipeline.LiveLister) error {
	if w, ok := m.inner.(pipeline.ManifestWatcher); ok {
		return w.ListChanged(ctx, spec, live)
	}
	return nil
}

// Present implements pipeline.ToolScreen (FR-1.52): before a tool enters a
// session catalog the active rule sets are applied again, so a rule-set
// change after import takes effect. The first blocking result per server
// revision, tool and rule-set versions is recorded as metadata_blocked.
func (in *Inspector) Present(ctx context.Context, server, serverRevision string, t *mcp.Tool) error {
	if !in.metadataScan {
		return nil
	}
	others := in.otherNames()
	own := others[server]
	fs := in.ScanTool(server, t, own, others)
	if !blocking(fs) {
		return nil
	}
	key := suspendKey(server, serverRevision, t.Name) + "\x00" + in.ruleSet(RuleSetMetadata).Version + "\x00" + in.ruleSet(RuleSetUnicode).Version
	st := SuspendedTool{Server: server, ServerRevision: serverRevision, Tool: t.Name, Stage: "presentation", Findings: fs}
	in.meta.mu.Lock()
	first := !in.meta.reported[key]
	in.meta.reported[key] = true
	in.meta.suspended[suspendKey(server, serverRevision, t.Name)] = st
	in.meta.mu.Unlock()
	if first {
		in.recordBlocked(ctx, "presentation", "E-08", st)
	}
	return fmt.Errorf("tool %s of %s blocked by the metadata scan (%s)", t.Name, server, fs[0].Rule)
}
