package hostile

import (
	"os"
	"testing"
)

// SelfFlag as the first argument makes the test binary run as the hostile
// fixture server (FR-19.1: the fixture is built into the test binary). The
// Gateway under test launches `<test binary> -smcp-hostile -fixture HF-xx`.
const SelfFlag = "-smcp-hostile"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == SelfFlag {
		os.Exit(Main([]string{os.Args[0], SelfFlag}, os.Args[2:]))
	}
	os.Exit(m.Run())
}
