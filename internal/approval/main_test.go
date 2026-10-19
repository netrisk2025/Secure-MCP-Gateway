package approval

import (
	"os"
	"strings"
	"testing"
)

// notifierOutEnv makes the test binary act as a command notifier: it writes
// its two arguments to the named file and exits. Tests point
// approvals.notify_command at the test binary instead of writing a script,
// because executing a file this process has just written can fail with
// ETXTBSY when another goroutine forks at the same time.
const notifierOutEnv = "SMCP_APPROVAL_TEST_NOTIFIER_OUT"

func TestMain(m *testing.M) {
	if out := os.Getenv(notifierOutEnv); out != "" {
		if err := os.WriteFile(out, []byte(strings.Join(os.Args[1:], "\n")+"\n"), 0o600); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
