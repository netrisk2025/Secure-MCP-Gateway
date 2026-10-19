// Command agents is the real-agent conformance suite (SRS FR-15.8). It
// bootstraps a Gateway with the reference server in a temporary directory,
// signs each agent in non-interactively, drives the real agent CLI (Claude
// Code, Codex CLI, Hermes Agent, OpenCode, Gemini CLI, Goose) with one short
// scripted prompt per scenario, and decides every result from the Gateway's
// evidence journal, never from the model's text. It writes build/agents.json
// (the status-data `agents` array) and build/agents-report.json.
//
//	go run ./scripts/agents                       # every installed client, models via the Vercel AI Gateway
//	go run ./scripts/agents -clients claude-code,codex
//	go run ./scripts/agents -local                # Claude Code and Codex use your subscription logins
//	go run ./scripts/agents -approval-acceptance docs/verification/FR-3.25-transcript.md
//
// See docs/agents-conformance.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

type options struct {
	clients  string
	local    bool
	out      string
	report   string
	work     string
	keep     bool
	matrix   string
	timeout  time.Duration
	maxTurns int
	// dnsOnlyCA reissues the instance CA without the CP-53 iPAddress name
	// constraints (diagnostic for BoringSSL-based clients).
	dnsOnlyCA bool
	// brokenGateway runs the clients against a deliberately broken Gateway
	// build (FR-15.8) and expects every client that runs to fail.
	brokenGateway bool
	extra         []*client // test hook: clients outside the matrix (the reference client)
}

func main() {
	var o options
	flag.StringVar(&o.clients, "clients", "", "comma-separated client IDs (default: every client of the matrix); IDs: "+strings.Join(clientIDs(), ", ")+", reference")
	flag.BoolVar(&o.local, "local", false, "use the subscription logins of Claude Code and Codex instead of the Vercel AI Gateway")
	flag.StringVar(&o.out, "out", "build/agents.json", "status-data results (STATUS CONTRACT agents array)")
	flag.StringVar(&o.report, "report", "build/agents-report.json", "per-scenario report")
	flag.StringVar(&o.work, "work", "", "work directory (default: a new temporary directory)")
	flag.BoolVar(&o.keep, "keep", false, "keep the work directory (agent output, smcpd.log, journal)")
	flag.StringVar(&o.matrix, "matrix", "docs/clients/matrix.json", "client matrix with pinned versions (FR-15.10)")
	flag.DurationVar(&o.timeout, "timeout", 4*time.Minute, "time limit for one agent prompt")
	flag.IntVar(&o.maxTurns, "max-turns", 4, "agent turn limit per prompt, where the client supports one")
	flag.BoolVar(&o.dnsOnlyCA, "dns-only-ca", false, "DIAGNOSTIC: reissue the instance CA with DNS-only name constraints (deviates from CP-53; labelled in the results)")
	flag.BoolVar(&o.brokenGateway, "broken-gateway", false, "FR-15.8 broken-build check: build smcpd with -tags smcp_broken and exit 0 only if every client that runs reaches the Gateway and fails")
	acceptance := flag.String("approval-acceptance", "", "FR-3.25: run the four approval cases with Claude Code only and write the Markdown transcript to this file")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *acceptance != "" {
		if err := runApprovalAcceptance(ctx, o, *acceptance, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "agents: approval acceptance:", err)
			os.Exit(1)
		}
		return
	}
	results, err := run(ctx, o, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agents:", err)
		os.Exit(2)
	}
	if o.brokenGateway {
		if err := brokenVerdict(lastReports); err != nil {
			fmt.Fprintln(os.Stderr, "agents: broken-build check FAILED:", err)
			os.Exit(1)
		}
		fmt.Println("broken-build check passed: every client that ran turned to fail")
		return
	}
	for _, r := range results {
		if r.Result == resultFail {
			os.Exit(1)
		}
	}
}

func clientIDs() []string {
	var ids []string
	for _, c := range allClients() {
		ids = append(ids, c.ID)
	}
	return ids
}

// selectClients returns the clients named in list (all when empty).
func selectClients(list string, extra []*client) ([]*client, error) {
	all := append(append(allClients(), referenceClient()), extra...)
	if strings.TrimSpace(list) == "" {
		return allClients(), nil
	}
	var out []*client
	for _, id := range strings.Split(list, ",") {
		id = strings.TrimSpace(id)
		i := slices.IndexFunc(all, func(c *client) bool { return c.ID == id })
		if i < 0 {
			return nil, fmt.Errorf("unknown client %q (known: %s)", id, strings.Join(clientIDs(), ", "))
		}
		out = append(out, all[i])
	}
	return out, nil
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found above the current directory")
		}
		dir = parent
	}
}

func run(ctx context.Context, o options, stdout io.Writer) ([]agentResult, error) {
	logf := func(format string, a ...any) { fmt.Fprintf(stdout, "==> "+format+"\n", a...) }
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(root, p)
	}
	clients, err := selectClients(o.clients, o.extra)
	if err != nil {
		return nil, err
	}
	pinned, err := loadPinned(abs(o.matrix))
	if err != nil {
		return nil, err
	}

	work := o.work
	if work == "" {
		if work, err = os.MkdirTemp("", "smcp-agents-"); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, err
	}
	if !o.keep && o.work == "" {
		defer os.RemoveAll(work)
	}

	// Decide which clients can run before starting anything.
	reports := make([]*clientReport, len(clients))
	var runnable []*client
	for i, c := range clients {
		r := &clientReport{agentResult: agentResult{Client: c.Name, Mode: c.mode(o.local), Result: resultNotRun}, Pinned: pinned[c.Name]}
		if o.dnsOnlyCA {
			r.Mode += "+dns-only-ca"
		}
		if o.brokenGateway {
			r.Mode += "+broken-gateway"
		}
		reports[i] = r
		bin := ""
		switch {
		case c.NotRunReason != "":
			r.Detail = c.NotRunReason
		case c.run != nil:
			r.Version = "in-process"
		default:
			if bin = findBin(c.Bins); bin == "" {
				r.Detail = "not installed (" + strings.Join(c.Bins, ", ") + " not found)"
				break
			}
			r.Version = clientVersion(ctx, bin)
			if r.Mode == modeAIGateway && c.NeedsKey != "" && os.Getenv(c.NeedsKey) == "" {
				r.Detail = c.NeedsKey + " is not set; no model credentials"
				if c.LocalLogin {
					r.Detail += " (or run with -local)"
				}
			}
		}
		r.bin = bin
		if r.Detail == "" {
			runnable = append(runnable, c)
		} else {
			logf("%s: not-run: %s", c.Name, r.Detail)
		}
	}

	if len(runnable) > 0 {
		g, err := startGateway(ctx, root, work, runnable, o.dnsOnlyCA, o.brokenGateway, logf)
		if err != nil {
			return nil, err
		}
		defer g.stop()
		bundle := filepath.Join(work, "ca-bundle.pem")
		if err := caBundle(bundle, g.ca); err != nil {
			return nil, err
		}
		approvals := g.approvalsAvailable(ctx)
		for i, c := range clients {
			if !slices.Contains(runnable, c) {
				continue
			}
			e := &runEnv{g: g, dir: filepath.Join(work, "agents", c.ID), local: o.local && c.LocalLogin,
				caBundle: bundle, maxTurns: o.maxTurns, bin: reports[i].bin}
			runClient(ctx, c, e, reports[i], approvals, o.timeout, logf)
		}
		g.stop()
		vout, verr := g.verifyJournal(ctx)
		logf("journal verify: %s", vout)
		for _, r := range reports {
			if r.Result == resultNotRun {
				continue
			}
			if verr != nil {
				r.Result = resultFail
				r.Detail += "; journal verify FAILED: " + verr.Error()
			} else {
				r.Detail += "; journal verify ok"
			}
		}
		if o.keep || o.work != "" {
			logf("work directory kept: %s", work)
		}
	}

	results := make([]agentResult, len(reports))
	for i, r := range reports {
		if r.Pinned != "" && r.Version != "" && r.Version != "in-process" && r.Version != r.Pinned {
			r.Detail += fmt.Sprintf("; version %s differs from pinned %s", r.Version, r.Pinned)
		}
		results[i] = r.agentResult
	}
	if err := writeOut(abs(o.out), results); err != nil {
		return nil, err
	}
	if o.report != "" {
		if err := writeOut(abs(o.report), reports); err != nil {
			return nil, err
		}
	}
	printSummary(stdout, reports)
	lastReports = reports
	return results, nil
}

// lastReports holds the per-scenario reports of the last run, for the
// broken-build verdict.
var lastReports []*clientReport

// brokenVerdict decides the FR-15.8 broken-build check: at least one client
// ran, and every client that ran reached the Gateway (its allowed call
// passed, so the failure is not an outage or a missing tool) and failed.
func brokenVerdict(reports []*clientReport) error {
	ran := 0
	for _, r := range reports {
		if r.Result == resultNotRun {
			continue
		}
		ran++
		allowed := false
		for _, s := range r.Scenarios {
			if s.Scenario == scnAllowed && s.Result == resultPass {
				allowed = true
			}
		}
		switch {
		case r.Result != resultFail:
			return fmt.Errorf("%s passed against the broken Gateway: %s", r.Client, r.Detail)
		case !allowed:
			return fmt.Errorf("%s failed without reaching the Gateway, which proves nothing: %s", r.Client, r.Detail)
		}
	}
	if ran == 0 {
		return errors.New("no client ran")
	}
	return nil
}

func writeOut(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func printSummary(w io.Writer, reports []*clientReport) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-14s %-12s %-12s %-8s %s\n", "CLIENT", "VERSION", "MODE", "RESULT", "DETAIL")
	for _, r := range reports {
		fmt.Fprintf(w, "%-14s %-12s %-12s %-8s %s\n", r.Client, orDash(r.Version), r.Mode, r.Result, r.Detail)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// loadPinned reads client -> pinnedVersion from matrix.json (FR-15.10). A
// missing file yields no pins.
func loadPinned(path string) (map[string]string, error) {
	pins := map[string]string{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return pins, nil
	}
	if err != nil {
		return nil, err
	}
	var m struct {
		Clients []struct {
			Client        string  `json:"client"`
			PinnedVersion *string `json:"pinnedVersion"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, c := range m.Clients {
		if c.PinnedVersion != nil {
			pins[c.Client] = *c.PinnedVersion
		}
	}
	return pins, nil
}
