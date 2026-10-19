package approval

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Notifier delivers an OS desktop notification (X-14). The Approval
// Service passes only the public tool name, the server alias, the approval
// ID and the console URL; arguments never reach a notification (FR-3.23).
type Notifier interface {
	Notify(ctx context.Context, title, body string) error
}

// Off is the notifier that does nothing (notify = "off").
type Off struct{}

// Notify implements Notifier.
func (Off) Notify(context.Context, string, string) error { return nil }

// commandNotifier runs a notifier program.
type commandNotifier struct {
	name string
	args func(title, body string) []string
}

func (c commandNotifier) Notify(ctx context.Context, title, body string) error {
	path, err := exec.LookPath(c.name)
	if err != nil {
		return fmt.Errorf("desktop notifier %q not found: %w", c.name, err)
	}
	out, err := exec.CommandContext(ctx, path, c.args(title, body)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("desktop notifier %q: %w: %s", c.name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// appleScriptString quotes s as an AppleScript string literal.
func appleScriptString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ", "\r", " ").Replace(s) + `"`
}

var (
	osascript = commandNotifier{"osascript", func(t, b string) []string {
		return []string{"-e", "display notification " + appleScriptString(b) + " with title " + appleScriptString(t)}
	}}
	terminalNotifier = commandNotifier{"terminal-notifier", func(t, b string) []string { return []string{"-title", t, "-message", b} }}
	notifySend       = commandNotifier{"notify-send", func(t, b string) []string { return []string{"--app-name=smcpd", "--", t, b} }}
)

// NewNotifier returns the notifier selected by the [approvals] notify key
// for the running platform. "auto" picks terminal-notifier or osascript on
// macOS and notify-send on Linux, and Off elsewhere; a missing program is
// reported when a notification is sent, never at start, so the approval
// flow does not depend on it.
func NewNotifier(mode, command string) (Notifier, error) {
	switch mode {
	case "", "auto":
		switch runtime.GOOS {
		case "darwin":
			if _, err := exec.LookPath("terminal-notifier"); err == nil {
				return terminalNotifier, nil
			}
			return osascript, nil
		case "linux":
			return notifySend, nil
		}
		return Off{}, nil
	case "off":
		return Off{}, nil
	case "osascript":
		return osascript, nil
	case "terminal-notifier":
		return terminalNotifier, nil
	case "notify-send":
		return notifySend, nil
	case "command":
		if command == "" {
			return nil, errors.New("approvals.notify = \"command\" needs approvals.notify_command")
		}
		return commandNotifier{command, func(t, b string) []string { return []string{t, b} }}, nil
	}
	return nil, fmt.Errorf("approvals.notify %q is not a known notifier", mode)
}

// notificationText is the X-14 text of a new approval.
func notificationText(r *Record) (title, body string) {
	return "Secure MCP Gateway: approval needed",
		fmt.Sprintf("%s on server %s needs approval. Approval ID %s. Open %s", r.PublicName, r.Server, r.ID, r.URL)
}
