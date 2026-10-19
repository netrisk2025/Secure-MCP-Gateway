// Command smcp-workload is the reference workload generator of SRS
// FR-11.1: it writes the reference dataset and runs the FR-11 performance
// measurements with eight concurrent callers against real smcpd
// instances.
//
//	smcp-workload generate --out DIR
//	    writes DIR/policy.json (10,000 rule and registry nodes, 256 candidate
//	    rules per decision) and DIR/dataset.json; with --state DIR also the
//	    100,000-event, 30-day Evidence Journal into a bootstrapped state
//	    directory that smcpd has not opened yet.
//	smcp-workload run --bin DIR --out perf.json [--test-json perf-test.json]
//	    [--calls 2000] [--decisions 100000] [--queries 100] [--idle 10m]
//
// The measurements are of the machine they run on; perf.json records the
// host and marks whether it is the recorded reference hardware.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/perf"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "smcp-workload:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: smcp-workload generate|run [flags]")
	}
	switch args[0] {
	case "generate":
		return generate(args[1:])
	case "run":
		return measure(args[1:])
	}
	return fmt.Errorf("unknown command %q (generate or run)", args[0])
}

func generate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	out := fs.String("out", "", "directory for policy.json and dataset.json")
	state := fs.String("state", "", "bootstrapped state directory to write the reference journal into (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	doc, err := perf.ReferencePolicy("workload-r1", perf.RefRules, perf.RefCandidates)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "policy.json"), doc, 0o644); err != nil {
		return err
	}
	rules, candidates, err := perf.CountRules(doc, "read-only", "ref")
	if err != nil {
		return err
	}
	ds := perf.Dataset{Rules: rules, RegistryNodes: perf.RefRegistryNodes, Candidates: candidates, Days: perf.RefDays, Callers: perf.RefCallers}
	if *state != "" {
		if ds.Events, err = perf.WriteJournal(*state, perf.RefEvents, perf.RefDays, time.Now()); err != nil {
			return err
		}
	}
	b, _ := json.MarshalIndent(ds, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "dataset.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("reference dataset: %d rule and registry nodes (%d rules, %d registry), %d candidate rules per decision, %d events, %d callers\n",
		ds.Nodes(), ds.Rules, ds.RegistryNodes, ds.Candidates, ds.Events, ds.Callers)
	return nil
}

func measure(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	o := perf.RunOptions{Log: os.Stderr}
	fs.StringVar(&o.BinDir, "bin", "", "directory with smcpd, smcpctl and smcp-refserver")
	out := fs.String("out", "build/perf.json", "results file")
	testJSON := fs.String("test-json", "", "also write the results as go test -json events (for tools/reqreport)")
	fs.IntVar(&o.Calls, "calls", 2000, "tool calls per load measurement")
	fs.IntVar(&o.Decisions, "decisions", 100000, "decisions for FR-11.2")
	fs.IntVar(&o.Queries, "queries", 100, "repetitions of the console query set")
	fs.DurationVar(&o.Idle, "idle", 10*time.Minute, "time from start to the idle memory sample")
	fs.StringVar(&o.Commit, "commit", os.Getenv("GITHUB_SHA"), "commit measured")
	work := fs.String("work", "", "work directory (default a new temporary directory, removed afterwards)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.BinDir == "" {
		return fmt.Errorf("--bin is required")
	}
	if *work == "" {
		d, err := os.MkdirTemp("", "smcp-workload-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(d)
		*work = d
	}
	o.Work = *work
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := perf.Run(ctx, o)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	for _, m := range res.Measurements {
		fmt.Printf("%-8s %-32s %s %.3f %s (budget %.3f) pass=%v\n", m.Requirement, m.Name, m.Metric, m.Value, m.Unit, m.Budget, m.Pass)
	}
	if *testJSON != "" {
		f, err := os.Create(*testJSON)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := perf.WriteTestJSON(f, "github.com/ethan03805/secure-mcp-gateway/internal/perf/run", res.Measurements, time.Now()); err != nil {
			return err
		}
	}
	return nil
}
