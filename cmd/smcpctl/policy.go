package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/policyadmin"
)

const policyUsage = `usage: smcpctl policy <command> [flags]

  validate <file>                 validate a policy document (offline)
  diff <file>                     compare a document with the active revision
  diff --from <rev> --to <rev>    compare two published revisions
  simulate <file>                 replay recent journal calls against the document
       [--scenario <file.jsonl>]  replay a JSON Lines scenario instead
       [--limit N] [--all]        journal calls to replay; include unchanged results
  publish <file>                  sign, store and activate the document
       [--parent <rev>] [--simulation <id>]
  rollback <rev> [--as <new-rev>] publish the content of <rev> as a new revision
  history                         list published revisions, newest first
  show [rev] [--document]         show a revision record (default: active)
  reload                          publish the configured policy file

Commands other than validate talk to the running Gateway's control API.
Every command takes --config <file> (default smcp.toml).
`

// policyCmd dispatches `smcpctl policy ...`.
func policyCmd(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, policyUsage)
		return errors.New("policy: missing command")
	}
	rest := args[1:]
	switch args[0] {
	case "validate":
		return policyValidate(rest, out)
	case "diff":
		return policyDiff(rest, out)
	case "simulate":
		return policySimulate(rest, out)
	case "publish":
		return policyPublish(rest, out)
	case "rollback":
		return policyRollback(rest, out)
	case "history":
		return policyHistory(rest, out)
	case "show":
		return policyShow(rest, out)
	case "help", "-h", "--help":
		fmt.Fprint(out, policyUsage)
		return nil
	}
	fmt.Fprint(out, policyUsage)
	return fmt.Errorf("policy: unknown command %q", args[0])
}

// parseInterleaved parses flags that may appear before or after the
// positional arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func policyClient(cfgPath string) (*adminClient, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	return newAdminClient(cfg, true)
}

func readDocument(path string) (json.RawMessage, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%s is not JSON", path)
	}
	return raw, nil
}

func policyValidate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	fs.String("config", "smcp.toml", "configuration file (unused; validation is offline)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: smcpctl policy validate <file>")
	}
	raw, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	_, sum, err := policyadmin.Summarize(raw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "policy OK: revision %s, digest %s, %d framework profiles, %d templates, %d rules, %d grants\n",
		sum.Revision, sum.Digest, sum.Profiles, sum.Templates, sum.Rules, sum.Grants)
	return nil
}

func policyDiff(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy diff", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	from := fs.String("from", "", "published revision to compare from (default the active revision)")
	to := fs.String("to", "", "published revision to compare to (instead of a file)")
	jsonOut := fs.Bool("json", false, "print the JSON report")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	body := map[string]any{}
	switch {
	case len(pos) == 1 && *to == "":
		doc, err := readDocument(pos[0])
		if err != nil {
			return err
		}
		body["document"] = doc
	case len(pos) == 0 && *to != "":
		body["to"] = *to
	default:
		return errors.New("usage: smcpctl policy diff <file> | --to <rev> [--from <rev>]")
	}
	if *from != "" {
		body["from"] = *from
	}
	c, err := policyClient(*cfgPath)
	if err != nil {
		return err
	}
	res, _, err := c.do("POST", "/api/v1/policy/diff", body)
	if err != nil {
		return err
	}
	if *jsonOut {
		printJSON(out, res)
		return nil
	}
	var rep policy.DiffReport
	if err := remarshal(res, &rep); err != nil {
		return err
	}
	fmt.Fprintf(out, "from %s to %s: %d changes", rep.From, rep.To, len(rep.Changes))
	if rep.Widening {
		fmt.Fprint(out, " (widens authority)")
	}
	fmt.Fprintln(out)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, ch := range rep.Changes {
		where := ch.Profile
		if ch.Template != "" {
			where = ch.Template
			if ch.Server != "" {
				where += " " + ch.Server + "/" + ch.Tool
			}
		}
		detail := ch.After
		if ch.Before != "" && ch.After != "" {
			detail = ch.Before + " -> " + ch.After
		} else if ch.Before != "" {
			detail = ch.Before
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", ch.Kind, where, detail)
	}
	return tw.Flush()
}

func remarshal(in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func policySimulate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy simulate", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	scenario := fs.String("scenario", "", "JSON Lines scenario file (default: recent journal calls)")
	limit := fs.Int("limit", 0, "number of recent journal calls to replay (default 1000)")
	all := fs.Bool("all", false, "include fixtures whose decision did not change")
	jsonOut := fs.Bool("json", false, "print the JSON report")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: smcpctl policy simulate <file> [--scenario <file.jsonl>] [--limit N] [--all]")
	}
	doc, err := readDocument(pos[0])
	if err != nil {
		return err
	}
	body := map[string]any{"document": doc, "all": *all}
	if *limit > 0 {
		body["limit"] = *limit
	}
	if *scenario != "" {
		f, err := os.Open(*scenario)
		if err != nil {
			return err
		}
		fx, err := policy.ParseFixtures(f)
		f.Close()
		if err != nil {
			return err
		}
		if len(fx) == 0 {
			return fmt.Errorf("%s has no fixtures", *scenario)
		}
		body["fixtures"] = fx
	}
	c, err := policyClient(*cfgPath)
	if err != nil {
		return err
	}
	res, _, err := c.do("POST", "/api/v1/policy/simulate", body)
	if err != nil {
		return err
	}
	if *jsonOut {
		printJSON(out, res)
		return nil
	}
	var rep policyadmin.SimulationResult
	if err := remarshal(res, &rep); err != nil {
		return err
	}
	fmt.Fprintf(out, "simulation %s: %d fixtures from %s, active %s, candidate %s: %d changed",
		rep.SimulationID, rep.Fixtures, rep.Source, rep.ActiveRevision, rep.CandidateRevision, rep.Changed)
	for _, k := range []string{policy.SimPermitToDeny, policy.SimDenyToPermit, policy.SimReason, policy.SimObligations} {
		if n := rep.Counts[k]; n > 0 {
			fmt.Fprintf(out, ", %s %d", k, n)
		}
	}
	fmt.Fprintln(out)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, r := range rep.Results {
		f := r.Fixture
		fmt.Fprintf(tw, "%d\t%s\t%s %s/%s\t%s %s\t->\t%s %s\n", r.Index, r.Change, f.Template, f.Server, f.Tool,
			r.Active.Outcome, r.Active.ReasonCode, r.Candidate.Outcome, r.Candidate.ReasonCode)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "cite it when publishing: smcpctl policy publish %s --simulation %s\n", pos[0], rep.SimulationID)
	return nil
}

func policyPublish(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy publish", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	parent := fs.String("parent", "", "refuse unless this is the active revision")
	sim := fs.String("simulation", "", "simulation ID to record with the revision")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: smcpctl policy publish <file> [--parent <rev>] [--simulation <id>]")
	}
	doc, err := readDocument(pos[0])
	if err != nil {
		return err
	}
	c, err := policyClient(*cfgPath)
	if err != nil {
		return err
	}
	body := map[string]any{"document": doc}
	if *parent != "" {
		body["parent"] = *parent
	}
	if *sim != "" {
		body["simulation_ref"] = *sim
	}
	res, _, err := c.do("POST", "/api/v1/policy/revisions", body)
	if err != nil {
		return err
	}
	return printPublish(out, res)
}

func printPublish(out io.Writer, res map[string]any) error {
	var r policyadmin.PublishResult
	if err := remarshal(res, &r); err != nil {
		return err
	}
	if !r.Created {
		fmt.Fprintf(out, "revision %s is already active; nothing changed\n", r.Record.Revision)
		return nil
	}
	fmt.Fprintf(out, "published and activated revision %s (sequence %d, parent %s, digest %s, key %s)\n",
		r.Record.Revision, r.Record.Sequence, orNone(r.Record.Parent), r.Record.Digest, r.Record.KeyID)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func policyRollback(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy rollback", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	as := fs.String("as", "", "revision ID of the new revision (default <rev>-rb<n>)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: smcpctl policy rollback <rev> [--as <new-rev>]")
	}
	c, err := policyClient(*cfgPath)
	if err != nil {
		return err
	}
	body := map[string]any{"to": pos[0]}
	if *as != "" {
		body["revision"] = *as
	}
	res, _, err := c.do("POST", "/api/v1/policy/rollback", body)
	if err != nil {
		return err
	}
	return printPublish(out, res)
}

func policyHistory(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy history", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	jsonOut := fs.Bool("json", false, "print the JSON listing")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	c, err := policyClient(*cfgPath)
	if err != nil {
		return err
	}
	res, _, err := c.do("GET", "/api/v1/policy/revisions", nil)
	if err != nil {
		return err
	}
	if *jsonOut {
		printJSON(out, res)
		return nil
	}
	var list struct {
		Active    string `json:"active"`
		Revisions []struct {
			Revision    string `json:"revision"`
			Sequence    int    `json:"sequence"`
			Parent      string `json:"parent"`
			Actor       string `json:"actor"`
			PublishedAt string `json:"published_at"`
			Origin      string `json:"origin"`
			RollbackOf  string `json:"rollback_of"`
		} `json:"revisions"`
	}
	if err := remarshal(res, &list); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\tSEQ\tREVISION\tPARENT\tORIGIN\tACTOR\tPUBLISHED")
	for _, r := range list.Revisions {
		mark := ""
		if r.Revision == list.Active {
			mark = "*"
		}
		origin := r.Origin
		if r.RollbackOf != "" {
			origin += " of " + r.RollbackOf
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n", mark, r.Sequence, r.Revision, orNone(r.Parent), origin, r.Actor, r.PublishedAt)
	}
	return tw.Flush()
}

func policyShow(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	docOnly := fs.Bool("document", false, "print only the canonical policy document (export)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: smcpctl policy show [rev] [--document]")
	}
	id := "active"
	if len(pos) == 1 {
		id = pos[0]
	}
	c, err := policyClient(*cfgPath)
	if err != nil {
		return err
	}
	res, _, err := c.do("GET", "/api/v1/policy/revisions/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if *docOnly {
		b, err := json.Marshal(res["document"])
		if err != nil {
			return err
		}
		canon, err := policy.Canonical(b)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(canon))
		return nil
	}
	printJSON(out, res)
	return nil
}
