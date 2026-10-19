package sandbox

import (
	"os/exec"
	"syscall"
)

// setParentDeath kills the attached Podman client if the Gateway dies, so
// that the instance loses its stdin and stops.
func setParentDeath(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
