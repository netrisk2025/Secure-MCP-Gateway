// Package linux embeds the Linux Enforced-profile installation files
// (install-enforced.sh, setup-server-identity.sh, the systemd units, the
// nftables ruleset and the AppArmor profiles) so that `smcpctl install
// --profile enforced` can run the same installer from a release archive,
// which does not ship this directory.
package linux

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed install-enforced.sh setup-server-identity.sh systemd/*.service nftables/smcp.nft apparmor/smcpd apparmor/smcp-server
var files embed.FS

// Files returns the embedded tree.
func Files() fs.FS { return files }

// Extract writes the embedded tree into dir with the same layout: the
// script mode 0755, every other file 0644.
func Extract(dir string) error {
	return fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if filepath.Ext(p) == ".sh" {
			mode = 0o755
		}
		return os.WriteFile(dst, b, mode)
	})
}
