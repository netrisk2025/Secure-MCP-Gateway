package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

const serversUsage = `usage: smcpctl servers <list|show|suspended-tools> [flags]

  list              configured servers and their registry state
  show <alias>      one server with its tools and its suspended tools
  suspended-tools   tools the Local Server Registry holds as suspended by the
                    import-time metadata scan (SR-5.9-2), one per line:
                    server, revision, tool, reason and the blocking rules

Every subcommand takes --config <file> (default smcp.toml).
`

// serversCmd reads the Local Server Registry through the control API
// (GET /api/v1/servers, GET /api/v1/servers/{alias}).
func serversCmd(args []string, out io.Writer) error {
	if len(args) < 1 {
		fmt.Fprint(out, serversUsage)
		return errors.New("servers: subcommand required")
	}
	fs := flag.NewFlagSet("servers "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	rest := args[1:]
	alias := ""
	if args[0] == "show" {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return errors.New("servers show: alias required")
		}
		alias, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		return control([]string{"--config", *cfgPath}, out, "GET", "/api/v1/servers", nil)
	case "show":
		return control([]string{"--config", *cfgPath}, out, "GET", "/api/v1/servers/"+url.PathEscape(alias), nil)
	case "suspended-tools":
		return suspendedTools(*cfgPath, out)
	}
	fmt.Fprint(out, serversUsage)
	return fmt.Errorf("servers: unknown subcommand %q", args[0])
}

func suspendedTools(cfgPath string, out io.Writer) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	c, err := newAdminClient(cfg, true)
	if err != nil {
		return err
	}
	res, _, err := c.do("GET", "/api/v1/servers", nil)
	if err != nil {
		return err
	}
	servers, _ := res["servers"].([]any)
	n := 0
	for _, s := range servers {
		sv, _ := s.(map[string]any)
		tools, _ := sv["suspended_tools"].([]any)
		for _, t := range tools {
			tv, _ := t.(map[string]any)
			var rules []string
			findings, _ := tv["findings"].([]any)
			for _, f := range findings {
				fv, _ := f.(map[string]any)
				if tag, _ := fv["tag"].(bool); tag {
					continue
				}
				rules = append(rules, fmt.Sprintf("%v/%v@%v", fv["ruleSet"], fv["rule"], fv["ruleSetVersion"]))
			}
			fmt.Fprintf(out, "%v\t%v\t%v\t%v\t%s\n", sv["alias"], sv["revision"], tv["name"], tv["reason_code"], strings.Join(rules, ","))
			n++
		}
	}
	fmt.Fprintf(out, "%d suspended tools\n", n)
	return nil
}
