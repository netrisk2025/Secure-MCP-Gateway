package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/harness"
	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox"
)

// errFindings makes smcpctl exit non-zero after doctor printed findings.
var errFindings = errors.New("doctor reported findings")

func lockdownCmd(args []string, out io.Writer) error {
	usage := "usage: smcpctl lockdown <apply|remove|show> <client> [--dry-run]\nclients: " + strings.Join(harness.IDs(), ", ")
	if len(args) < 2 {
		return errors.New(usage)
	}
	action := args[0]
	pos, rest := splitArgs(args[1:])
	fs := flag.NewFlagSet("lockdown", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	dry := fs.Bool("dry-run", false, "show the changes without writing anything")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(usage)
	}
	cl, ok := harness.Lookup(pos[0])
	if !ok {
		return fmt.Errorf("unknown client %q; known: %s", pos[0], strings.Join(harness.IDs(), ", "))
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	e, err := harnessEnv(cfg)
	if err != nil {
		return err
	}
	switch action {
	case "apply", "show":
		p, err := cl.Lockdown(e)
		if err != nil {
			return err
		}
		if *dry || action == "show" {
			fmt.Fprint(out, harness.Describe(p))
			return nil
		}
		return applyPlan(out, p, e.Home, "lockdown")
	case "remove":
		mp := harness.ManifestPath(e.Home, cl.ID, "lockdown")
		if _, err := os.Stat(mp); err != nil {
			return fmt.Errorf("no lockdown applied for %s (%s)", cl.ID, mp)
		}
		if *dry {
			fmt.Fprintln(out, "would restore the files listed in", mp)
			return nil
		}
		m, err := harness.Remove(mp)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s lockdown removed: %d files restored\n", cl.ID, len(m.Files))
		return nil
	}
	return errors.New(usage)
}

func doctorCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	asJSON := fs.Bool("json", false, "print the findings as JSON")
	var only multiFlag
	fs.Var(&only, "client", "check only this client (repeatable); default every installed client")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	e, err := harnessEnv(cfg)
	if err != nil {
		return err
	}
	r := harness.Doctor(e, only, doctorPrereq(cfg))
	if *asJSON {
		printJSON(out, r)
	} else {
		harness.WriteText(out, r)
	}
	if r.Failed() {
		return errFindings
	}
	return nil
}

// doctorPrereq reports the enforced-profile prerequisites from the sandbox
// element (sandbox.Doctor, also `smcpctl runtime doctor`). A failed
// prerequisite is a failing finding when the configuration asks for the
// Enforced profile, and information otherwise.
var doctorPrereq = func(cfg *config.Config) harness.Prereq {
	return func() []harness.Finding {
		var out []harness.Finding
		for _, c := range sandbox.Doctor(context.Background(), sandbox.DoctorOptions{}) {
			if c.Status == sandbox.CheckPass {
				continue
			}
			kind := harness.KindInfo
			if c.Status == sandbox.CheckFail && cfg.Profile.Mode == "enforced" {
				kind = harness.KindPrereq
			}
			msg := "enforced-profile prerequisite " + c.ID + " (" + c.Name + "): " + c.Status
			if c.Detail != "" {
				msg += ": " + c.Detail
			}
			if c.Remedy != "" {
				msg += "; " + c.Remedy
			}
			out = append(out, harness.Finding{Kind: kind, Message: msg})
		}
		return out
	}
}
