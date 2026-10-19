package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"
)

const egressUsage = `usage: smcpctl egress <status|grants|connections> [flags]

  status        broker limits and attached instances (enforced or advisory)
  grants        current egress grants  [--server <alias>]
  connections   recent egress operations, newest first
                [--server <alias>] [--denied] [--limit <n>] [--since <RFC 3339 time>]

Every subcommand takes --config <file> (default smcp.toml).
`

// egressCmd reads the Egress Broker's state through the control API
// (docs/api/egress.md).
func egressCmd(args []string, out io.Writer) error {
	if len(args) < 1 {
		fmt.Fprint(out, egressUsage)
		return errors.New("egress: subcommand required")
	}
	fs := flag.NewFlagSet("egress "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	server := fs.String("server", "", "only this server alias")
	denied := fs.Bool("denied", false, "only refused or terminated operations")
	limit := fs.Int("limit", 0, "at most this many records (default 100)")
	since := fs.String("since", "", "only records at or after this RFC 3339 time")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	q := url.Values{}
	var path string
	switch args[0] {
	case "status":
		path = "/api/v1/egress"
	case "grants":
		path = "/api/v1/egress/grants"
		if *server != "" {
			q.Set("server", *server)
		}
	case "connections":
		path = "/api/v1/egress/connections"
		if *server != "" {
			q.Set("server", *server)
		}
		if *denied {
			q.Set("decision", "denied")
		}
		if *limit > 0 {
			q.Set("limit", strconv.Itoa(*limit))
		}
		if *since != "" {
			q.Set("since", *since)
		}
	default:
		fmt.Fprint(out, egressUsage)
		return fmt.Errorf("egress: unknown subcommand %q", args[0])
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return control([]string{"--config", *cfgPath}, out, "GET", path, nil)
}
