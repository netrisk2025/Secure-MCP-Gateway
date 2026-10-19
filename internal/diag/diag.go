// Package diag builds the diagnostic logger: operational messages for the
// person running the Gateway, at a configurable level, on standard error.
// Diagnostic logs are not evidence. Security events go to the evidence
// journal (internal/audit) whatever the log level, and diagnostic messages
// must not carry secrets, tokens or tool arguments.
package diag

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// New returns a logger writing to w at level ("debug", "info", "warn",
// "error") in format ("text" or "json"). The returned LevelVar changes the
// level at run time.
func New(w io.Writer, level, format string) (*slog.Logger, *slog.LevelVar, error) {
	lv := new(slog.LevelVar)
	if err := SetLevel(lv, level); err != nil {
		return nil, nil, err
	}
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, nil, fmt.Errorf("log format %q: want text or json", format)
	}
	return slog.New(h).With("component", "smcpd"), lv, nil
}

// SetLevel parses and applies a level name.
func SetLevel(lv *slog.LevelVar, level string) error {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return fmt.Errorf("log level %q: want debug, info, warn or error", level)
	}
	lv.Set(l)
	return nil
}

// Discard is a logger that drops everything (tests).
func Discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
