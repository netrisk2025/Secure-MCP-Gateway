package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

const approvalsUsage = `usage: smcpctl approvals <subcommand> [flags]

  list [--state pending|approved|denied|expired|consumed|all] [--json]
  show <id> [--json]
  approve <id> [--comment text] [--yes]
  deny <id> [--comment text] [--yes]
  watch [--max-events n]

Without --user the command uses the local operator token (Administrator).
With --user <name> it signs in as that Approver account ([[approvals.account]])
and reads the password from --password-file or a prompt.

Common flags: --config <file> (default smcp.toml), --user, --password-file.
`

var (
	approvalID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	listStates = map[string]bool{"pending": true, "approved": true, "denied": true, "expired": true, "consumed": true, "all": true}
)

// approvalsCmd implements smcpctl approvals (FR-3.24).
func approvalsCmd(args []string, stdin io.Reader, out io.Writer) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("approvals "+sub, flag.ContinueOnError)
	fs.SetOutput(out)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	user := fs.String("user", "", "sign in as this Approver account instead of using the operator token")
	pwFile := fs.String("password-file", "", "read the Approver password from this file (- for standard input)")
	state := fs.String("state", "pending", "list: state to list, or all")
	asJSON := fs.Bool("json", false, "list, show: print JSON")
	comment := fs.String("comment", "", "approve, deny: comment recorded with the decision")
	yes := fs.Bool("yes", false, "approve, deny: do not ask for confirmation after showing the evidence")
	maxEvents := fs.Int("max-events", 0, "watch: exit after this many approval events (0: run until interrupted)")
	id := ""
	if (sub == "show" || sub == "approve" || sub == "deny") && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if id == "" && fs.NArg() > 0 {
		id = fs.Arg(0)
	}
	if !listStates[*state] {
		return fmt.Errorf("--state must be pending, approved, denied, expired, consumed or all")
	}
	switch sub {
	case "list", "watch":
	case "show", "approve", "deny":
		if id == "" {
			return fmt.Errorf("approvals %s needs an approval ID", sub)
		}
		if !approvalID.MatchString(id) {
			return fmt.Errorf("%q is not an approval ID", id)
		}
	case "help":
		fmt.Fprint(out, approvalsUsage)
		return nil
	default:
		return fmt.Errorf("unknown approvals subcommand %q\n%s", sub, approvalsUsage)
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := approvalsClient(cfg, *user, *pwFile)
	if err != nil {
		return err
	}
	if *user != "" {
		defer func() { _, _, _ = c.do("POST", "/api/v1/approvals/logout", map[string]any{}) }()
	}
	switch sub {
	case "list":
		res, _, err := c.do("GET", "/api/v1/approvals?state="+*state, nil)
		if err != nil {
			return err
		}
		if *asJSON {
			printJSON(out, res)
			return nil
		}
		printList(out, res["approvals"])
		return nil
	case "show":
		res, _, err := c.do("GET", "/api/v1/approvals/"+id, nil)
		if err != nil {
			return err
		}
		if *asJSON {
			printJSON(out, res)
		} else {
			printEvidence(out, res)
		}
		return nil
	case "approve", "deny":
		return decideCmd(c, stdin, out, id, sub, *comment, *yes)
	}
	return watchCmd(c, out, *maxEvents)
}

// approvalsClient returns a control API client with the operator token, or
// signed in as an Approver.
func approvalsClient(cfg *config.Config, user, pwFile string) (*adminClient, error) {
	if user == "" {
		return newAdminClient(cfg, true)
	}
	c, err := newAdminClient(cfg, false)
	if err != nil {
		return nil, err
	}
	pw, err := readSecret(pwFile, "Password for Approver "+user, false)
	if err != nil {
		return nil, err
	}
	res, _, err := c.do("POST", "/api/v1/approvals/login", map[string]any{"username": user, "password": pw})
	if err != nil {
		return nil, err
	}
	tok, _ := res["token"].(string)
	if tok == "" {
		return nil, errors.New("sign-in returned no token")
	}
	c.token = tok
	return c, nil
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func printList(out io.Writer, v any) {
	items, _ := v.([]any)
	if len(items) == 0 {
		fmt.Fprintln(out, "no approvals")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tTOOL\tSERVER\tPRINCIPAL\tEXPIRES")
	for _, it := range items {
		m, _ := it.(map[string]any)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", str(m, "id"), str(m, "state"), str(m, "public_name"), str(m, "server"), str(m, "principal_id"), str(m, "expires_at"))
	}
	tw.Flush()
}

// anomalyText is the anomaly evidence of an approval (FR-3.18): band,
// contributing feature, z-score and baseline snapshot, or "none reported"
// when the call was not held for an anomaly band.
func anomalyText(m map[string]any) string {
	a, ok := m["anomaly"].(map[string]any)
	if !ok || str(a, "band") == "" {
		return "none reported"
	}
	s := "band " + str(a, "band")
	if f := str(a, "contributing_feature"); f != "" {
		s += ", feature " + f
	}
	if z, ok := a["z_score"].(float64); ok {
		s += fmt.Sprintf(", z-score %.2f", z)
	}
	if id := str(a, "snapshot_id"); id != "" {
		s += ", snapshot " + id
	}
	return s
}

// printEvidence prints the FR-3.18 evidence of an approval.
func printEvidence(out io.Writer, m map[string]any) {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "%s\t%s\n", k, v)
		}
	}
	row("Approval", str(m, "id"))
	row("State", str(m, "state"))
	row("Tool", str(m, "public_name"))
	row("Server", str(m, "server")+" (backend tool "+str(m, "tool")+")")
	row("Server revision", str(m, "server_revision"))
	row("Tool revision", str(m, "tool_revision"))
	row("Manifest", str(m, "manifest_source"))
	row("Policy revision", str(m, "policy_revision"))
	if rules, ok := m["decisive_rules"].([]any); ok && len(rules) > 0 {
		parts := make([]string, len(rules))
		for i, r := range rules {
			parts[i] = fmt.Sprint(r)
		}
		row("Decisive rules", strings.Join(parts, ", "))
	}
	row("Anomaly", anomalyText(m))
	row("Session", str(m, "session_id"))
	row("Principal", str(m, "principal_id"))
	row("Template", str(m, "template"))
	row("Requested", str(m, "created_at"))
	row("Expires", str(m, "expires_at"))
	row("Decided by", str(m, "decided_by"))
	row("Decided at", str(m, "decided_at"))
	row("Comment", str(m, "comment"))
	row("Consumed at", str(m, "consumed_at"))
	row("Arguments digest", str(m, "arguments_digest"))
	row("Console", str(m, "approval_url"))
	tw.Flush()
	args, _ := json.MarshalIndent(m["arguments"], "  ", "  ")
	fmt.Fprintf(out, "Arguments:\n  %s\n", args)
}

// decideCmd shows the evidence, asks for confirmation unless --yes, then
// approves or denies.
func decideCmd(c *adminClient, stdin io.Reader, out io.Writer, id, verb, comment string, yes bool) error {
	rec, _, err := c.do("GET", "/api/v1/approvals/"+id, nil)
	if err != nil {
		return err
	}
	printEvidence(out, rec)
	if s := str(rec, "state"); s != "pending" {
		return fmt.Errorf("approval %s is %s, not pending", id, s)
	}
	if !yes {
		fmt.Fprintf(out, "%s this call? [y/N] ", strings.ToUpper(verb[:1])+verb[1:])
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return errors.New("not confirmed; nothing changed")
		}
	}
	res, _, err := c.do("POST", "/api/v1/approvals/"+id+"/"+verb, map[string]any{"comment": comment})
	if err != nil {
		return err
	}
	past := map[string]string{"approve": "approved", "deny": "denied"}[verb]
	fmt.Fprintf(out, "%s %s by %s at %s\n", past, id, str(res, "decided_by"), str(res, "decided_at"))
	return nil
}

// watchCmd follows the watch stream and prints one line per event.
func watchCmd(c *adminClient, out io.Writer, maxEvents int) error {
	req, err := http.NewRequest("GET", c.base+"/api/v1/approvals/watch", nil) //nolint:gosec // G704: the configured loopback control API
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "text/event-stream")
	hc := *c.http
	hc.Timeout = 0          // the stream stays open
	resp, err := hc.Do(req) //nolint:gosec // G704: the configured loopback control API
	if err != nil {
		return fmt.Errorf("control API at %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("control API: watch refused (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	name, seen := "", 0
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m); err != nil {
				continue
			}
			ts := time.Now().Format(time.RFC3339)
			if name == "snapshot" {
				items, _ := m["approvals"].([]any)
				fmt.Fprintf(out, "%s watching; %d pending\n", ts, len(items))
				for _, it := range items {
					a, _ := it.(map[string]any)
					fmt.Fprintf(out, "%s pending %s %s on %s expires %s %s\n", ts, str(a, "id"), str(a, "public_name"), str(a, "server"), str(a, "expires_at"), str(a, "approval_url"))
				}
				continue
			}
			a, _ := m["approval"].(map[string]any)
			fmt.Fprintf(out, "%s %s %s %s on %s expires %s %s\n", ts, str(m, "type"), str(a, "id"), str(a, "public_name"), str(a, "server"), str(a, "expires_at"), str(a, "approval_url"))
			seen++
			if maxEvents > 0 && seen >= maxEvents {
				return nil
			}
		}
	}
	return sc.Err()
}
