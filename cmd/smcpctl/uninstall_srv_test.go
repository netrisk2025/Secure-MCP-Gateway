package main

import (
	"io/fs"
	"strings"
	"testing"

	linuxpkg "github.com/ethan03805/secure-mcp-gateway/packaging/linux"
)

// TestUninstallKnowsServerIdentityFiles: uninstall removes exactly the
// files that setup-server-identity.sh writes, and the enforced
// configuration that install writes runs servers as smcp-srv.
func TestUninstallKnowsServerIdentityFiles(t *testing.T) {
	script, err := fs.ReadFile(linuxpkg.Files(), "setup-server-identity.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range serverIdentityFiles {
		if !strings.Contains(string(script), p) {
			t.Errorf("setup-server-identity.sh does not write %s", p)
		}
	}
	for _, p := range []string{"/etc/sudoers.d/smcp-srv", "smcpd.service.d/smcp-srv.conf"} {
		found := false
		for _, f := range serverIdentityFiles {
			found = found || strings.HasSuffix(f, p)
		}
		if !found {
			t.Errorf("uninstall does not remove %s", p)
		}
	}
}
