//go:build !linux

package sandbox

import "os/exec"

// setParentDeath has no equivalent outside Linux. The sandbox runs only on
// Linux; on other systems only the tests' fake Podman uses this path.
func setParentDeath(*exec.Cmd) {}
