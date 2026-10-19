package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
)

const graphUsage = `usage: smcpctl graph <subcommand> [flags]

  status [--json]                     mirror state, schema, checkpoint, counts, engine findings
  rebuild [--yes]                     wipe the graph mirror and rebuild it from the journal
  query [<name>] [--param k=v] [--limit n] [--json]
                                      run a read-only canned query (no name: list them)
  neighborhood <label> <id> [--limit n] [--json]
                                      bounded one-hop neighborhood of a node
  config                              print neo4j.conf settings for the [graph] budget (offline)

Common flag: --config <file> (default smcp.toml).
`

type paramFlags []string

func (p *paramFlags) String() string     { return strings.Join(*p, ",") }
func (p *paramFlags) Set(v string) error { *p = append(*p, v); return nil }

var graphParamName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)

// graphCmd implements smcpctl graph (E-25, E-26, E-28).
func graphCmd(args []string, stdin io.Reader, out io.Writer) error {
	sub := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = append(pos, args[0]), args[1:]
	}
	fs := flag.NewFlagSet("graph "+sub, flag.ContinueOnError)
	fs.SetOutput(out)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	asJSON := fs.Bool("json", false, "print JSON")
	yes := fs.Bool("yes", false, "rebuild: do not ask for confirmation")
	limit := fs.Int("limit", 0, "query, neighborhood: maximum rows (1..500, default 50)")
	var params paramFlags
	fs.Var(&params, "param", "query: parameter name=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pos = append(pos, fs.Args()...)
	if *limit < 0 || *limit > graph.MaxLimit {
		return fmt.Errorf("--limit must be 1..%d", graph.MaxLimit)
	}
	switch sub {
	case "help":
		fmt.Fprint(out, graphUsage)
		return nil
	case "status", "rebuild", "query", "neighborhood", "config":
	default:
		return fmt.Errorf("unknown graph subcommand %q\n%s", sub, graphUsage)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if sub == "config" {
		s, err := graph.Resolve(cfg)
		if err != nil {
			return err
		}
		port := 7687
		if u, err := url.Parse(s.URI); err == nil && u.Port() != "" {
			if n, err := strconv.Atoi(u.Port()); err == nil {
				port = n
			}
		}
		fmt.Fprint(out, graph.EngineConfig(s.Budget, port))
		return nil
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	lim := ""
	if *limit > 0 {
		lim = fmt.Sprintf("limit=%d", *limit)
	}
	switch sub {
	case "status":
		res, _, err := c.do("GET", "/api/v1/graph/status", nil)
		if err != nil {
			return err
		}
		if *asJSON {
			printJSON(out, res)
		} else {
			printGraphStatus(out, res)
		}
		return nil
	case "rebuild":
		if !*yes {
			fmt.Fprint(out, "Wipe the graph mirror and rebuild it from the evidence journal? [y/N] ")
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
				return fmt.Errorf("rebuild not confirmed")
			}
		}
		res, _, err := c.do("POST", "/api/v1/graph/rebuild", map[string]any{})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "rebuild %v; follow it with smcpctl graph status\n", res["status"])
		return nil
	case "neighborhood":
		if len(pos) != 2 {
			return fmt.Errorf("graph neighborhood needs <label> <id>; labels: %s", strings.Join(graph.NeighborhoodLabels, ", "))
		}
		q := url.Values{"label": {pos[0]}, "id": {pos[1]}}
		if lim != "" {
			q.Set("limit", fmt.Sprint(*limit))
		}
		res, _, err := c.do("GET", "/api/v1/graph/neighborhood?"+q.Encode(), nil)
		if err != nil {
			return err
		}
		if *asJSON {
			printJSON(out, res)
			return nil
		}
		printNeighborhood(out, res)
		return nil
	}
	// query
	if len(pos) == 0 {
		res, _, err := c.do("GET", "/api/v1/graph/queries", nil)
		if err != nil {
			return err
		}
		if *asJSON {
			printJSON(out, res)
			return nil
		}
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tPARAMETERS\tDESCRIPTION")
		qs, _ := res["queries"].([]any)
		for _, x := range qs {
			m, _ := x.(map[string]any)
			var ps []string
			for _, p := range asSlice(m["params"]) {
				ps = append(ps, fmt.Sprint(p))
			}
			fmt.Fprintf(tw, "%v\t%s\t%v\n", m["name"], strings.Join(ps, ","), m["description"])
		}
		return tw.Flush()
	}
	q := url.Values{}
	for _, p := range params {
		k, v, ok := strings.Cut(p, "=")
		if !ok || !graphParamName.MatchString(k) {
			return fmt.Errorf("--param must be name=value, got %q", p)
		}
		q.Set(k, v)
	}
	if lim != "" {
		q.Set("limit", fmt.Sprint(*limit))
	}
	path := "/api/v1/graph/queries/" + url.PathEscape(pos[0])
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	res, _, err := c.do("GET", path, nil)
	if err != nil {
		return err
	}
	if *asJSON {
		printJSON(out, res)
		return nil
	}
	printRows(out, asSlice(res["rows"]))
	return nil
}

func asSlice(v any) []any { s, _ := v.([]any); return s }

// integral turns whole-number JSON numbers into int64 so that byte counts
// and timestamps print without an exponent.
func integral(v any) any {
	switch t := v.(type) {
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
	case map[string]any:
		for k, x := range t {
			t[k] = integral(x)
		}
	case []any:
		for i, x := range t {
			t[i] = integral(x)
		}
	}
	return v
}

func printGraphStatus(out io.Writer, s map[string]any) {
	integral(s)
	fmt.Fprintf(out, "state:     %v\n", s["state"])
	if e, ok := s["error"].(string); ok && e != "" {
		fmt.Fprintf(out, "error:     %s\n", e)
	}
	fmt.Fprintf(out, "database:  %v (%v)\n", s["uri"], s["database"])
	fmt.Fprintf(out, "schema:    %v (release supports %v)\n", s["schema_version"], s["supported_schema_version"])
	fmt.Fprintf(out, "templates: %v sha256:%v\n", s["template_set_version"], s["template_digest"])
	if cp, ok := s["checkpoint"].(map[string]any); ok {
		fmt.Fprintf(out, "journal:   segments before %v applied (%v events); last catch-up %v\n", cp["segment"], cp["events"], s["last_catch_up"])
	}
	fmt.Fprintf(out, "live:      %v applied, %v dropped (recovered by catch-up)\n", s["live_applied"], s["live_dropped"])
	if r, ok := s["last_retention"].(string); ok && r != "" {
		fmt.Fprintf(out, "retention: last %s, deleted %v\n", r, s["retention_deleted"])
	}
	if r, ok := s["last_rebuild"].(string); ok && r != "" {
		fmt.Fprintf(out, "rebuild:   last %s %v\n", r, s["rebuild_error"])
	}
	if m, ok := s["memory"].(map[string]any); ok {
		b, _ := m["budget"].(map[string]any)
		fmt.Fprintf(out, "memory:    heap %v of max %v (budget %v), page cache %v (budget %v), pressure %v\n",
			m["heap_used"], m["heap_max"], b["heap_bytes"], m["page_cache_configured"], b["page_cache_bytes"], m["pressure"])
	}
	if c, ok := s["counts"].(map[string]any); ok {
		keys := make([]string, 0, len(c))
		for k := range c {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, c[k]))
		}
		fmt.Fprintf(out, "nodes:     %s\n", strings.Join(parts, " "))
	}
	for _, f := range asSlice(s["hardening"]) {
		m, _ := f.(map[string]any)
		fmt.Fprintf(out, "finding:   %v = %v, want %v (%v)\n", m["setting"], m["value"], m["want"], m["reason"])
	}
}

func printNeighborhood(out io.Writer, nb map[string]any) {
	integral(nb)
	node, _ := nb["node"].(map[string]any)
	fmt.Fprintf(out, "%v %v (degree %v, truncated %v)\n", node["labels"], node["id"], nb["degree"], nb["truncated"])
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TYPE\tFROM\tTO")
	for _, e := range asSlice(nb["edges"]) {
		m, _ := e.(map[string]any)
		fmt.Fprintf(tw, "%v\t%v\t%v\n", m["type"], m["from"], m["to"])
	}
	_ = tw.Flush()
}

func printRows(out io.Writer, rows []any) {
	integral(rows)
	if len(rows) == 0 {
		fmt.Fprintln(out, "(no rows)")
		return
	}
	first, _ := rows[0].(map[string]any)
	cols := make([]string, 0, len(first))
	for k := range first {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.ToUpper(strings.Join(cols, "\t")))
	for _, r := range rows {
		m, _ := r.(map[string]any)
		vals := make([]string, len(cols))
		for i, c := range cols {
			if m[c] == nil {
				vals[i] = "-"
			} else {
				vals[i] = fmt.Sprint(m[c])
			}
		}
		fmt.Fprintln(tw, strings.Join(vals, "\t"))
	}
	_ = tw.Flush()
}
