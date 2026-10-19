package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const approversUsage = `usage: smcpctl approvers <command> [flags]

  list            Session Approver accounts of smcp.toml and the principal directory
  add NAME        create a Session Approver (FR-2.23); the password is read from
                  --password-file (mode 0600) or a prompt, never from the command line,
                  and must differ from the Administrator's password
  rm NAME         remove a Session Approver of the directory and end its console sessions

Session Approvers approve harness sign-ins in the browser (FR-2.19) and nothing else.
Every command takes --config <file> (default smcp.toml).
`

func approversCmd(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, approversUsage)
		return nil
	}
	for _, a := range args {
		if a == "--password" || a == "-password" || strings.HasPrefix(a, "--password=") || strings.HasPrefix(a, "-password=") {
			return errors.New("passwords are never accepted on the command line; use --password-file or the prompt")
		}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return control(rest, out, "GET", "/api/v1/approvers", nil)
	case "add", "rm":
	default:
		return fmt.Errorf("unknown approvers command %q\n%s", sub, approversUsage)
	}
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		return fmt.Errorf("approvers %s needs a username first", sub)
	}
	name, rest := rest[0], rest[1:]
	if sub == "rm" {
		fs := flag.NewFlagSet("approvers rm", flag.ContinueOnError)
		cfgPath := fs.String("config", "smcp.toml", "configuration file")
		reason := fs.String("reason", "", "reason recorded with the removal")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return control([]string{"--config", *cfgPath}, out, "POST", "/api/v1/approvers/"+url.PathEscape(name)+"/remove", map[string]any{"reason": *reason})
	}
	fs := flag.NewFlagSet("approvers add", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	file := fs.String("password-file", "", "read the password from this file (mode 0600)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	pw, err := readPassword(*file, "Session Approver password (12 or more characters, not the Administrator's)", true)
	if err != nil {
		return err
	}
	return control([]string{"--config", *cfgPath}, out, "POST", "/api/v1/approvers", map[string]any{"username": name, "password": pw})
}
