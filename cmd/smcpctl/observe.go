package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

const observeUsage = `usage: smcpctl observe <subcommand> [flags]

  status [--json]
  anomalies [--since 24h] [--band elevated|abnormal|critical] [--limit n] [--json]
  baseline [list] [--json]
  baseline build
  baseline show <id>
  baseline drift <id>
  baseline promote <id>        (promoting an older snapshot is a rollback)
  baseline rollback <id>
  baseline flag <session-id> [--reason text]
  baseline unflag <session-id>
  campaign list [--json]
  campaign create --file spec.json
  campaign show <id>
  campaign submit|approve|reject|stop|expire <id> [--reason text]
  export --format csv|jsonl|parquet|graphml [--campaign id] [--from t] [--to t]
         [--principal p] [--server s] [--tool t] [--parameters a,b] [--snapshot id]
         [--subgraph behavior-model|audit] [--download dir]
  exports [--json]

Times are RFC 3339 or a duration back from now (for example 24h).
Every subcommand uses the local operator token. Common flag: --config <file>.
`

var observeID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// observeCmd implements smcpctl observe (SS-10 analytics).
func observeCmd(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, observeUsage)
		return nil
	}
	sub, args := args[0], args[1:]
	verb := ""
	if (sub == "baseline" || sub == "campaign") && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		verb, args = args[0], args[1:]
	}
	id := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("observe "+sub, flag.ContinueOnError)
	fs.SetOutput(out)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	asJSON := fs.Bool("json", false, "print JSON")
	since := fs.String("since", "24h", "anomalies: start (RFC 3339 or duration back from now)")
	band := fs.String("band", "", "anomalies: only this band")
	limit := fs.Int("limit", 50, "anomalies: maximum rows")
	reason := fs.String("reason", "", "reason recorded with the action")
	file := fs.String("file", "", "campaign create: JSON campaign specification")
	format := fs.String("format", "", "export: csv, jsonl, parquet or graphml")
	campaign := fs.String("campaign", "", "export: campaign ID")
	from := fs.String("from", "", "export: start time")
	to := fs.String("to", "", "export: end time")
	params := fs.String("parameters", "", "export: comma-separated parameter IDs or names")
	snapshot := fs.String("snapshot", "", "export graphml: snapshot ID (default promoted)")
	subgraph := fs.String("subgraph", "", "export graphml: behavior-model (default) or audit")
	download := fs.String("download", "", "export: download the files into this directory")
	var principals, servers, tools multi
	fs.Var(&principals, "principal", "export: principal in scope (repeatable)")
	fs.Var(&servers, "server", "export: server alias in scope (repeatable)")
	fs.Var(&tools, "tool", "export: tool in scope (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if id == "" && fs.NArg() > 0 {
		id = fs.Arg(0)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	needID := func() error {
		if !observeID.MatchString(id) {
			return fmt.Errorf("observe %s %s needs an ID", sub, verb)
		}
		return nil
	}
	show := func(res map[string]any, err error, text func(map[string]any)) error {
		if err != nil {
			return err
		}
		if *asJSON || text == nil {
			printJSON(out, res)
			return nil
		}
		text(res)
		return nil
	}
	get := func(path string) (map[string]any, error) { r, _, err := c.do("GET", path, nil); return r, err }
	post := func(path string, body any) (map[string]any, error) {
		r, _, err := c.do("POST", path, body)
		return r, err
	}

	switch sub {
	case "status":
		res, err := get("/api/v1/observations/status")
		return show(res, err, func(r map[string]any) { printObserveStatus(out, r) })
	case "anomalies":
		q := url.Values{"from": {*since}, "limit": {fmt.Sprint(*limit)}}
		if *band != "" {
			q.Set("band", *band)
		}
		res, err := get("/api/v1/anomalies?" + q.Encode())
		return show(res, err, func(r map[string]any) {
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tBAND\tZ\tFEATURE\tPRINCIPAL\tTOOL\tCORRELATION")
			rows, _ := r["rows"].([]any)
			for _, x := range rows {
				m, _ := x.(map[string]any)
				fmt.Fprintf(tw, "%v\t%v\t%.2f\t%v\t%v\t%v\t%v\n", m["ts"], m["band"], m["combined"], m["contributing_feature"], m["principal_id"], m["tool_name"], m["correlation_id"])
			}
			tw.Flush()
		})
	case "baseline":
		switch verb {
		case "", "list":
			res, err := get("/api/v1/baselines")
			return show(res, err, func(r map[string]any) {
				st, _ := r["status"].(map[string]any)
				fmt.Fprintf(out, "promoted: %v  contexts: %v (characterized %v)  learned: %v\n", obsOrNone(st["promoted"]), st["contexts"], st["characterized"], st["learned"])
				tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tCREATED\tTRIGGER\tRECORDS\tCONTEXTS\tPROMOTED")
				snaps, _ := r["snapshots"].([]any)
				for _, x := range snaps {
					m, _ := x.(map[string]any)
					fmt.Fprintf(tw, "%v\t%v\t%v\t%v\t%v\t%v\n", m["id"], m["created_at"], m["trigger"], m["records"], m["contexts"], m["promoted"])
				}
				tw.Flush()
			})
		case "build":
			res, err := post("/api/v1/baselines/snapshots", map[string]any{})
			return show(res, err, nil)
		case "show", "drift":
			if err := needID(); err != nil {
				return err
			}
			path := "/api/v1/baselines/" + id
			if verb == "drift" {
				path += "/drift"
			}
			res, err := get(path)
			return show(res, err, nil)
		case "promote", "rollback":
			if err := needID(); err != nil {
				return err
			}
			res, err := post("/api/v1/baselines/"+id+"/promote", map[string]any{"comment": *reason})
			return show(res, err, nil)
		case "flag", "unflag":
			if id == "" {
				return errors.New("observe baseline " + verb + " needs a session ID")
			}
			res, err := post("/api/v1/baselines/flags", map[string]any{"session_id": id, "flagged": verb == "flag", "reason": *reason})
			return show(res, err, nil)
		}
	case "campaign":
		switch verb {
		case "", "list":
			res, err := get("/api/v1/research/campaigns")
			return show(res, err, func(r map[string]any) {
				tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tNAME\tSTATE\tSTART\tEND\tUSED/QUOTA")
				list, _ := r["campaigns"].([]any)
				for _, x := range list {
					m, _ := x.(map[string]any)
					fmt.Fprintf(tw, "%v\t%v\t%v\t%v\t%v\t%v/%v\n", m["id"], m["name"], m["state"], m["start"], m["end"], m["used_bytes"], m["quota_bytes"])
				}
				tw.Flush()
			})
		case "create":
			if *file == "" {
				return errors.New("observe campaign create needs --file spec.json")
			}
			raw, err := os.ReadFile(*file)
			if err != nil {
				return err
			}
			var spec map[string]any
			if err := json.Unmarshal(raw, &spec); err != nil {
				return fmt.Errorf("%s: %w", *file, err)
			}
			res, err := post("/api/v1/research/campaigns", spec)
			return show(res, err, nil)
		case "show":
			if err := needID(); err != nil {
				return err
			}
			res, err := get("/api/v1/research/campaigns/" + id)
			return show(res, err, nil)
		case "submit", "approve", "reject", "stop", "expire":
			if err := needID(); err != nil {
				return err
			}
			res, err := post("/api/v1/research/campaigns/"+id+"/"+verb, map[string]any{"reason": *reason})
			return show(res, err, nil)
		}
	case "exports":
		res, err := get("/api/v1/research/exports")
		return show(res, err, nil)
	case "export":
		if *format == "" {
			return errors.New("observe export needs --format csv, jsonl, parquet or graphml")
		}
		body := map[string]any{"format": *format}
		if *campaign != "" {
			body["campaign_id"] = *campaign
		}
		for k, v := range map[string]string{"from": *from, "to": *to} {
			if v != "" {
				body[k] = v
			}
		}
		if *snapshot != "" {
			body["snapshot_id"] = *snapshot
		}
		if *subgraph != "" {
			body["subgraph"] = *subgraph
		}
		if *params != "" {
			body["parameters"] = strings.Split(*params, ",")
		}
		if len(principals)+len(servers)+len(tools) > 0 {
			body["scope"] = map[string]any{"principals": principals, "servers": servers, "tools": tools}
		}
		res, err := post("/api/v1/research/exports", body)
		if err != nil {
			return err
		}
		if *download != "" {
			ds, _ := res["dataset_id"].(string)
			files, _ := res["files"].([]any)
			names := []string{"manifest.json", "SHA256SUMS"}
			for _, f := range files {
				if m, ok := f.(map[string]any); ok {
					names = append(names, fmt.Sprint(m["name"]))
				}
			}
			dir := filepath.Join(*download, ds)
			for _, n := range names {
				if err := c.downloadFile("/api/v1/research/exports/"+ds+"/files/"+n, filepath.Join(dir, n)); err != nil {
					return err
				}
			}
			fmt.Fprintf(out, "dataset %s: %v rows, downloaded to %s\n", ds, res["rows"], dir)
			return nil
		}
		return show(res, nil, nil)
	}
	fmt.Fprint(out, observeUsage)
	return fmt.Errorf("unknown observe subcommand %q", strings.TrimSpace(sub+" "+verb))
}

func obsOrNone(v any) any {
	if v == nil || v == "" {
		return "none"
	}
	return v
}

func printObserveStatus(out io.Writer, r map[string]any) {
	if r["enabled"] != true {
		fmt.Fprintln(out, "observation: disabled")
		return
	}
	col, _ := r["collector"].(map[string]any)
	fmt.Fprintf(out, "observation: enabled  policy %v  catalog %v  scoring %v  sampling %v\n", r["policy_id"], r["catalog_version"], r["scoring"], r["sampling_rate"])
	fmt.Fprintf(out, "collector: assembled %v  captured %v  pending %v  queue %v/%v\n", col["assembled"], col["captured"], col["pending"], col["queue_depth"], col["queue_capacity"])
	if st, ok := r["store"].(map[string]any); ok {
		fmt.Fprintf(out, "store: %v  %v bytes in %v files  %v\n", st["backend"], st["bytes"], st["files"], st["dir"])
	} else if e, ok := r["store_error"]; ok {
		fmt.Fprintf(out, "store: unavailable (%v)\n", e)
	}
	b, _ := r["baseline"].(map[string]any)
	fmt.Fprintf(out, "baseline: promoted %v  loaded %v  contexts %v  characterized %v  snapshots %v\n", obsOrNone(b["promoted"]), obsOrNone(r["loaded_snapshot"]), b["contexts"], b["characterized"], b["snapshots"])
	if e, ok := b["promoted_error"]; ok && e != "" {
		fmt.Fprintf(out, "baseline error: %v\n", e)
	}
	fmt.Fprintf(out, "drops: %v\n", r["drops"])
}

// downloadFile saves one control API file (0600).
func (c *adminClient) downloadFile(path, dest string) error {
	req, err := http.NewRequest("GET", c.base+path, nil) //nolint:gosec // G704: the configured loopback control API; path segments come from the API response
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req) //nolint:gosec // G704: see NewRequest above
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", path, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
