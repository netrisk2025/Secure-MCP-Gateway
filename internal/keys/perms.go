package keys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// PrivateFiles are the state files whose disclosure gives control of the
// Gateway: the CA and listener keys, the evidence signing keys and the
// local operator token.
var PrivateFiles = []string{CAKeyFile, CANextKeyFile, ServerKeyFile, EvidenceKeyFile, EvidencePendingKeyFile, AdminTokenFile}

// ErrPermissionsOpen is returned by CheckPrivate for a private file that
// other accounts can read or write.
var ErrPermissionsOpen = errors.New("private state file is accessible to other accounts")

// CheckPrivate refuses a state directory in which a private file exists
// with group or other permission bits. Ensure creates these files with
// mode 0600; a looser mode means they were copied, restored or changed by
// hand, and any local account could read the operator token or the
// signing keys. Missing files are not an error.
func CheckPrivate(stateDir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	for _, name := range PrivateFiles {
		p := filepath.Join(stateDir, name)
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", ErrPermissionsOpen, p)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return fmt.Errorf("%w: %s has mode %04o; run chmod 600 %s", ErrPermissionsOpen, p, perm, p)
		}
	}
	return nil
}
