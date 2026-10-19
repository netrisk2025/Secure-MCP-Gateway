package linux

import (
	"io/fs"
	"regexp"
	"testing"
)

// TestEmbeddedInstallerIsComplete: every file that install-enforced.sh
// reads from its own directory ("$here/...") is embedded, so the installer
// that `smcpctl install` extracts from a release binary finds them.
func TestEmbeddedInstallerIsComplete(t *testing.T) {
	script, err := fs.ReadFile(Files(), "install-enforced.sh")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`\$here/([A-Za-z0-9_./-]+)`).FindAllStringSubmatch(string(script), -1)
	if len(refs) == 0 {
		t.Fatal("no $here references found")
	}
	for _, r := range refs {
		if r[1][len(r[1])-1] == '/' {
			continue // a directory followed by a variable, checked below
		}
		if _, err := fs.Stat(Files(), r[1]); err != nil {
			t.Errorf("install-enforced.sh reads %s, which is not embedded", r[1])
		}
	}
	// Profiles are referenced through a loop variable.
	for _, p := range []string{"apparmor/smcpd", "apparmor/smcp-server", "setup-server-identity.sh"} {
		if _, err := fs.Stat(Files(), p); err != nil {
			t.Errorf("%s is not embedded", p)
		}
	}
}
