package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/diag"
	"github.com/ethan03805/secure-mcp-gateway/internal/filters"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

const filtersUsage = `usage: smcpctl filters <rules|export|scan> [flags]

  rules   list the rule sets (every version, digest, targets, version in effect)
  export  write the built-in rule sets to --dir as a starting point for rules_dir
  scan    run every filter of one stage over input and print the result as JSON
          (--stage request|response|metadata; input from --file or stdin)

--config <file> applies the [filters] section of a configuration (rules_dir,
rule_versions, paths, urls, sizes); without it the built-in rule sets are used.
`

// filtersCmd implements `smcpctl filters` (docs/filters.md).
func filtersCmd(args []string, stdin io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(filtersUsage))
	}
	switch args[0] {
	case "rules":
		return filtersRules(args[1:], out)
	case "export":
		return filtersExport(args[1:], out)
	case "scan":
		return filtersScan(args[1:], stdin, out)
	}
	return errors.New(strings.TrimSpace(filtersUsage))
}

func inspectorFor(cfgPath string, mutate func(*config.Filters)) (*filters.Inspector, error) {
	opts := filters.Options{Log: diag.Discard(), RequestBodyBytes: 1 << 20, ResultBytes: 8 << 20}
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return nil, err
		}
		opts = filters.OptionsFrom(cfg)
		opts.Log = diag.Discard()
	}
	if mutate != nil {
		mutate(&opts.Config)
	}
	return filters.New(opts)
}

func filtersRules(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("filters rules", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file whose [filters] section to apply")
	if err := fs.Parse(args); err != nil {
		return err
	}
	in, err := inspectorFor(*cfgPath, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%-18s %-12s %-6s %-9s %-7s %-7s %s\n", "RULE SET", "VERSION", "RULES", "IN EFFECT", "FP MAX", "FN MAX", "SHA-256")
	for _, rs := range in.Library().All() {
		eff := ""
		if in.RuleSet(rs.ID) == rs {
			eff = "yes"
		}
		fmt.Fprintf(out, "%-18s %-12s %-6d %-9s %-7.3f %-7.3f %s\n", rs.ID, rs.Version, len(rs.Rules), eff, rs.Targets.FalsePositiveRate, rs.Targets.FalseNegativeRate, rs.Digest)
	}
	return nil
}

func filtersExport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("filters export", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory to write (created; existing files are not overwritten)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("filters export: --dir is required")
	}
	written, err := filters.ExportEmbedded(*dir)
	if err != nil {
		return err
	}
	for _, p := range written {
		fmt.Fprintln(out, p)
	}
	return nil
}

// scanReport is the JSON output of `smcpctl filters scan`. It never echoes
// the input; Output is the transformed text after redaction.
type scanReport struct {
	Stage       string             `json:"stage"`
	Disposition string             `json:"disposition"`
	ReasonCode  string             `json:"reasonCode,omitempty"`
	Finding     string             `json:"finding,omitempty"`
	Filters     []scanRun          `json:"filters,omitempty"`
	Findings    []pipeline.Finding `json:"findings,omitempty"`
	Output      *string            `json:"output,omitempty"`
}

type scanRun struct {
	ID         string             `json:"id"`
	Version    string             `json:"version"`
	Action     string             `json:"action"`
	ReasonCode string             `json:"reasonCode,omitempty"`
	DurationUs int64              `json:"durationUs"`
	Findings   []pipeline.Finding `json:"findings,omitempty"`
}

func filtersScan(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("filters scan", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file whose [filters] section to apply")
	stage := fs.String("stage", "response", "request, response or metadata")
	file := fs.String("file", "", "input file (default stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var input []byte
	var err error
	if *file != "" {
		input, err = os.ReadFile(*file)
	} else {
		input, err = io.ReadAll(io.LimitReader(stdin, 16<<20))
	}
	if err != nil {
		return err
	}
	// Every built-in filter of the stage runs, including the optional ones.
	all := func(c *config.Filters) {
		c.MandatoryRequest = []string{filters.IDSizeLimit, filters.IDUnicodeControl, filters.IDSecretFingerprint, filters.IDPathCanonicalize, filters.IDURLCanonicalize, filters.IDInjectionDetect}
		c.MandatoryResponse = []string{filters.IDSizeLimit, filters.IDOutputSchema, filters.IDContentTypeGate, filters.IDSecretFingerprint, filters.IDUnicodeControl, filters.IDPIIDetect, filters.IDInjectionMarker}
	}
	in, err := inspectorFor(*cfgPath, all)
	if err != nil {
		return err
	}
	rep := scanReport{Stage: *stage, Disposition: "release"}
	switch *stage {
	case "metadata":
		var tool mcp.Tool
		if err := json.Unmarshal(input, &tool); err != nil {
			tool = mcp.Tool{Name: "input", Description: string(input)}
		}
		rep.Findings = in.ScanTool("input", &tool, nil, nil)
		for _, f := range rep.Findings {
			if !f.Tag {
				rep.Disposition = "suspend"
			}
		}
	case "request", "response":
		chain := pipeline.NewFilters()
		if err := in.Register(chain); err != nil {
			return err
		}
		call := &pipeline.Call{CorrelationID: "scan", Server: "scan", PublicName: "scan_input", InputSchema: map[string]any{"type": "object"}}
		if *stage == "request" {
			argsJSON := input
			if v := bytes.TrimSpace(input); len(v) == 0 || v[0] != '{' || !json.Valid(v) {
				argsJSON, _ = json.Marshal(map[string]string{"text": string(input)})
			}
			outArgs, _, v := chain.RunRequest(context.Background(), call, argsJSON)
			if v != nil {
				rep.Disposition, rep.ReasonCode, rep.Finding = "block", v.ReasonCode, v.Finding
			} else if !bytes.Equal(outArgs, argsJSON) {
				rep.Disposition = "transform"
				s := string(outArgs)
				rep.Output = &s
			}
		} else {
			res, _, v := chain.RunResponse(context.Background(), call, &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(input)}}})
			if v != nil {
				rep.Disposition, rep.ReasonCode, rep.Finding = "withhold", v.ReasonCode, v.Finding
			} else {
				rep.Disposition = call.Inspection.Disposition()
				if rep.Disposition == "redact" {
					if tc, ok := res.Content[0].(*mcp.TextContent); ok {
						rep.Output = &tc.Text
					}
				}
			}
		}
		for _, r := range call.Inspection.Runs() {
			rep.Filters = append(rep.Filters, scanRun{ID: r.Filter, Version: r.Version, Action: r.Action.String(), ReasonCode: r.ReasonCode,
				DurationUs: r.Duration.Microseconds(), Findings: r.Findings})
		}
	default:
		return fmt.Errorf("filters scan: unknown stage %q", *stage)
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
