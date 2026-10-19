package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox"
)

const runtimeUsage = `usage: smcpctl runtime <command> [flags]

Offline:
  doctor              check the enforced-profile prerequisites of this host
  spec                print the launch specification of every configured server

Control API (running Gateway):
  status              launcher, defaults and instance counts
  instances           the instance table
  show <id>           one instance with its observations and stderr tail
  kill <id>           stop an instance now (--reason text)

Every command takes --config <file> (default smcp.toml); doctor does not need it.
`

// runtimeCmd dispatches `smcpctl runtime ...` (E-15, E-16, E-17).
func runtimeCmd(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, runtimeUsage)
		if len(args) == 0 {
			return errors.New("runtime: a command is required")
		}
		return nil
	}
	switch args[0] {
	case "doctor":
		return runtimeDoctor(args[1:], out)
	case "spec":
		return runtimeSpec(args[1:], out)
	case "status":
		return control(args[1:], out, "GET", "/api/v1/runtime", nil)
	case "instances":
		return control(args[1:], out, "GET", "/api/v1/runtime/instances", nil)
	case "show":
		id, rest, err := runtimeID(args[1:])
		if err != nil {
			return err
		}
		return control(rest, out, "GET", "/api/v1/runtime/instances/"+url.PathEscape(id), nil)
	case "kill":
		id, rest, err := runtimeID(args[1:])
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("runtime kill", flag.ContinueOnError)
		reason := fs.String("reason", "", "reason recorded with the kill")
		cfgPath := fs.String("config", "smcp.toml", "configuration file")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return control([]string{"--config", *cfgPath}, out, "POST", "/api/v1/runtime/instances/"+url.PathEscape(id)+"/kill",
			map[string]any{"reason": *reason})
	default:
		fmt.Fprint(out, runtimeUsage)
		return fmt.Errorf("runtime: unknown command %q", args[0])
	}
}

func runtimeID(args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, errors.New("an instance ID is required (see smcpctl runtime instances)")
	}
	return args[0], args[1:], nil
}

func runtimeDoctor(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("runtime doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the checks as JSON")
	podman := fs.String("podman", "", "podman binary (default: runtime.podman of --config, then PATH)")
	cfgPath := fs.String("config", "", "configuration file (optional; read for runtime.podman)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var do sandbox.DoctorOptions
	if *cfgPath != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		do = sandbox.DoctorOptionsFor(cfg.Runtime)
	}
	if *podman != "" {
		do.Podman = *podman
	}
	checks := sandbox.Doctor(context.Background(), do)
	failed := sandbox.Failed(checks)
	if *asJSON {
		printJSON(out, map[string]any{"ready": len(failed) == 0, "checks": checks})
	} else {
		for _, c := range checks {
			line := fmt.Sprintf("%-4s  %-55s %s", strings.ToUpper(c.Status), c.Name, c.Detail)
			fmt.Fprintln(out, strings.TrimRight(line, " "))
			if c.Status != sandbox.CheckPass && c.Remedy != "" {
				fmt.Fprintln(out, "      remedy:", c.Remedy)
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d enforced-profile prerequisites missing", len(failed))
	}
	if !*asJSON {
		fmt.Fprintln(out, "enforced profile: all prerequisites present")
	}
	return nil
}

// egressListenerPlaceholder stands for the address of an Egress Broker
// listener, which the broker opens per instance at launch.
const egressListenerPlaceholder = "http://10.0.2.2:<port>"

// egressPreview returns the Egress Broker variables an instance of alias
// receives (FR-5.37): the proxy variables, unless [egress] proxy_env is
// false, and one base-URL variable per grant with an endpoint_env. The
// listener ports are chosen at launch, so the values are placeholders. It
// returns nil when the instance is not attached to the broker.
func egressPreview(cfg *config.Config, alias, network string) map[string]string {
	if !cfg.Egress.Enabled || network != "egress" {
		return nil
	}
	env := map[string]string{}
	if cfg.Egress.ProxyEnv == nil || *cfg.Egress.ProxyEnv {
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			env[k] = egressListenerPlaceholder
		}
		env["NO_PROXY"], env["no_proxy"] = "", ""
	}
	for _, g := range cfg.Egress.Grants {
		if g.Server == alias && g.EndpointEnv != "" {
			env[g.EndpointEnv] = egressListenerPlaceholder
		}
	}
	return env
}

// runtimeSpec prints the launch specification and Podman argument vector
// of every configured server without starting anything (FR-5.9
// inspection). Environment values are not printed, only their names; the
// Egress Broker variables (egress_env) are addresses, shown with a
// placeholder for the per-instance listener port.
func runtimeSpec(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("runtime spec", flag.ContinueOnError)
	cfgPath := fs.String("config", "smcp.toml", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	var specs []map[string]any
	var pkgs *library.Runtime
	defer func() {
		if pkgs != nil {
			_ = pkgs.Close()
		}
	}()
	for _, s := range cfg.Servers {
		if s.Package != "" { // E-13, E-14: the enabled revision's launch specification
			if pkgs == nil {
				if pkgs, err = library.OpenRuntime(cfg, nil); err != nil {
					return fmt.Errorf("server %q: package library: %w", s.Alias, err)
				}
			}
			if s, err = pkgs.Resolve(s, cfg.Runtime.Sandbox == "podman"); err != nil {
				return fmt.Errorf("server %q: %w", s.Alias, err)
			}
		}
		env, err := pipeline.MergeEnv(pipeline.BaseEnv(), s.Env, nil)
		if err != nil {
			return err
		}
		for k := range s.SecretEnv {
			env[k] = ""
		}
		srv := cfg.Runtime.FindServer(s.Alias)
		network := sandbox.NetworkNone
		if srv.Network == "egress" {
			network = sandbox.EgressNetworkMode // confined to the broker listeners before start
		}
		if srv.Scope == "" {
			srv.Scope = "shared"
		}
		ls, err := sandbox.Build(sandbox.BuildInput{Runtime: cfg.Runtime, Server: srv,
			Spec: pipeline.ServerSpec{Alias: s.Alias, Command: s.Command, Args: s.Args, Env: env, Dir: s.Dir, RiskClasses: s.RiskClasses, HighRisk: s.HighRisk(),
				Runtime: s.Runtime, ArtifactRoot: s.ArtifactRoot, Roots: backend.SpecRoots(s)},
			Network: network, EgressEnv: egressPreview(cfg, s.Alias, srv.Network),
			InstanceID: "<instance-id>", Gateway: "<gateway-id>",
			Rootfs: filepath.Join(cfg.State.Dir, "runtime", "rootfs"), StateDir: cfg.State.Dir})
		if err != nil {
			return fmt.Errorf("server %q: %w", s.Alias, err)
		}
		specs = append(specs, map[string]any{"launch_spec": ls, "podman_args": ls.PodmanArgs()})
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"sandbox": cfg.Runtime.Sandbox, "servers": specs})
}
