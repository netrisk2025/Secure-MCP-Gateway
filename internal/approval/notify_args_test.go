package approval

import (
	"slices"
	"testing"
)

// Notification text includes names a backend chose (the public tool name).
// notify-send must read it as the summary and body, never as options.
func TestNotifySendEndsOptions(t *testing.T) {
	args := notifySend.args("--icon=/tmp/x", "--urgency=critical body")
	i := slices.Index(args, "--")
	if i < 0 || !slices.Equal(args[i+1:], []string{"--icon=/tmp/x", "--urgency=critical body"}) {
		t.Fatalf("notify-send argv %q: title and body must follow --", args)
	}
	if got := appleScriptString("a\"b\\c\nd"); got != `"a\"b\\c d"` {
		t.Fatalf("AppleScript quoting %s", got)
	}
}
