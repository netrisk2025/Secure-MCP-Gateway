package config

import (
	"strings"
	"testing"
)

// TestRuntimeRunAs: runtime.run_as names the CP-46 server identity and
// needs the Podman sandbox and a shared directory outside the state
// directory; sudo and shared_dir without run_as are refused.
func TestRuntimeRunAs(t *testing.T) {
	const base = "[runtime]\nsandbox = \"podman\"\n"
	cfg, err := Parse([]byte(withBefore(base + "run_as = \"smcp-srv\"\nshared_dir = \"/var/lib/smcp/srv\"\nsudo = \"/usr/bin/sudo\"\n")))
	if err != nil {
		t.Fatal(err)
	}
	if r := cfg.Runtime; r.RunAs != "smcp-srv" || r.SharedDir != "/var/lib/smcp/srv" || r.Sudo != "/usr/bin/sudo" {
		t.Fatalf("runtime %+v", r)
	}
	for name, c := range map[string]struct{ extra, want string }{
		"no shared dir":       {base + "run_as = \"smcp-srv\"\n", "shared_dir"},
		"no podman sandbox":   {"[runtime]\nsandbox = \"none\"\nrun_as = \"smcp-srv\"\nshared_dir = \"/srv/x\"\n", "sandbox"},
		"bad name":            {base + "run_as = \"Smcp Srv\"\nshared_dir = \"/srv/x\"\n", "run_as"},
		"relative sudo":       {base + "run_as = \"smcp-srv\"\nshared_dir = \"/srv/x\"\nsudo = \"sudo\"\n", "sudo"},
		"comma in shared dir": {base + "run_as = \"smcp-srv\"\nshared_dir = \"/srv/a,b\"\n", "shared_dir"},
		"shared dir in state": {"[state]\ndir = \"/var/lib/smcp/state\"\n" + base + "run_as = \"smcp-srv\"\nshared_dir = \"/var/lib/smcp/state/srv\"\n", "state directory"},
		"shared dir alone":    {base + "shared_dir = \"/srv/x\"\n", "only with runtime.run_as"},
		"cgroupfs":            {base + "run_as = \"smcp-srv\"\nshared_dir = \"/srv/x\"\ncgroup_manager = \"cgroupfs\"\n", "systemd user manager"},
		"sudo alone":          {base + "sudo = \"/usr/bin/sudo\"\n", "only with runtime.run_as"},
	} {
		if _, err := Parse([]byte(withBefore(c.extra))); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want an error naming %q)", name, err, c.want)
		}
	}
}
