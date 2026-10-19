package backend

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func obj(props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props}
}

func str(extra ...string) map[string]any {
	m := map[string]any{"type": "string"}
	if len(extra) == 2 {
		m[extra[0]] = extra[1]
	}
	return m
}

// TestToolDefinitionDriftHandling is FR-5.22: a backend serving a tool
// with each defect (null inputSchema, a non-object schema, a 65-character
// property name, a property name with a space, a nested invalid property
// name, and each violation of the MCP x-mcp-header constraints) is treated
// as drift: the server revision is not enabled, the reason names the tool
// and the rule, its tools are not in the catalog, and the other servers
// run. Valid definitions, with x-mcp-header on statically reachable
// primitive properties, are enabled.
func TestToolDefinitionDriftHandling(t *testing.T) {
	reqtest.Verifies(t, "FR-5.22")
	valid := map[string]any{
		"plain":  obj(map[string]any{"file.path-1": str()}),
		"header": obj(map[string]any{"region": str("x-mcp-header", "Region"), "n": map[string]any{"type": "integer", "x-mcp-header": "Count"}, "nested": obj(map[string]any{"flag": map[string]any{"type": "boolean", "x-mcp-header": "Flag"}})}),
	}
	defects := map[string]struct {
		schema any
		rule   string
	}{
		"null":          {nil, "null"},
		"array type":    {map[string]any{"type": "array"}, "not object"},
		"long name":     {obj(map[string]any{strings.Repeat("p", 65): str()}), "outside 1-64"},
		"space":         {obj(map[string]any{"has space": str()}), "outside 1-64"},
		"nested name":   {obj(map[string]any{"o": obj(map[string]any{"bad/name": str()})}), "outside 1-64"},
		"empty header":  {obj(map[string]any{"a": str("x-mcp-header", "")}), "empty"},
		"header token":  {obj(map[string]any{"a": str("x-mcp-header", "Bad Header")}), "token|invalid character"},
		"header CRLF":   {obj(map[string]any{"a": str("x-mcp-header", "A\r\nB")}), "token|invalid character"},
		"header dup":    {obj(map[string]any{"a": str("x-mcp-header", "Same"), "b": str("x-mcp-header", "same")}), "repeats|duplicate"},
		"header number": {obj(map[string]any{"a": map[string]any{"type": "number", "x-mcp-header": "Num"}}), "not integer, string or boolean|primitive types"},
		"header object": {obj(map[string]any{"a": map[string]any{"type": "object", "x-mcp-header": "Obj"}}), "not integer, string or boolean|primitive types"},
		"header items":  {obj(map[string]any{"a": map[string]any{"type": "array", "items": str("x-mcp-header", "Item")}}), "reachable"},
		"header anyOf":  {obj(map[string]any{"a": map[string]any{"anyOf": []any{str("x-mcp-header", "Any")}}}), "reachable"},
		"header root":   {map[string]any{"type": "object", "x-mcp-header": "Root"}, "reachable"},
		"header $defs":  {map[string]any{"type": "object", "$defs": map[string]any{"d": str("x-mcp-header", "Def")}}, "reachable"},
	}
	var servers []config.Server
	raw := map[string]func(context.Context, io.Reader, io.Writer) error{}
	add := func(alias string, schema any) {
		servers = append(servers, config.Server{Alias: alias, Command: "/fake/" + alias})
		b, _ := json.Marshal(schema)
		rs := &schemaServer{schema: string(b)}
		raw["/fake/"+alias] = rs.serve
	}
	aliasOf := map[string]string{}
	i := 0
	for name, d := range defects {
		alias := "d" + string(rune('a'+i))
		i++
		aliasOf[alias] = name
		add(alias, d.schema)
	}
	for name, schema := range valid {
		add("ok"+name, schema)
	}
	caps := pipeline.NewCapabilities(time.Minute)
	r, err := Start(context.Background(), servers, Options{Limits: Limits{PerPrincipal: 1, Total: 1, Queue: 1, UpstreamTimeout: 5 * time.Second, ResultBytes: 1 << 16},
		Launcher: pipeline.InProcessLauncher{Raw: raw}, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	disabled := r.Disabled()
	for alias, name := range aliasOf {
		reason := disabled[alias]
		matched := false
		for _, alt := range strings.Split(defects[name].rule, "|") { // the Gateway's or the SDK client's wording
			matched = matched || strings.Contains(reason, alt)
		}
		if !strings.Contains(reason, "drift") || !strings.Contains(reason, `tool "t"`) || !matched {
			t.Errorf("%s: reason %q, want drift with %q", name, reason, defects[name].rule)
		}
		if r.Resolve(alias+"_t") != nil {
			t.Errorf("%s: tool in the catalog", name)
		}
	}
	for name := range valid {
		if disabled["ok"+name] != "" || r.Resolve("ok"+name+"_t") == nil {
			t.Errorf("valid %s: disabled %q", name, disabled["ok"+name])
		}
	}
}

// schemaServer is a scripted stdio server with one tool "t" whose
// inputSchema is the given JSON text, which an SDK server would refuse to
// serve.
type schemaServer struct{ schema string }

func (ss *schemaServer) serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var m rawMsg
		if json.Unmarshal(sc.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue
		}
		var res string
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(m.Params, &p)
			res = fmt.Sprintf(`{"protocolVersion":%q,"capabilities":{"tools":{}},"serverInfo":{"name":"schema","version":"1"}}`, p.ProtocolVersion)
		case "tools/list":
			res = `{"tools":[{"name":"t","inputSchema":` + ss.schema + `}]}`
		default:
			res = `{}`
		}
		if _, err := fmt.Fprintf(out, `{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", m.ID, res); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return sc.Err()
}
