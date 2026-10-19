package diag

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// RotatingFile is the diagnostic log file (D-14): JSON Lines appended to
// path, rotated when a write would take it past maxBytes, keeping at most
// keep rotated files named path.1 (newest) to path.<keep> (FR-17.2, CP-50).
// It is safe for concurrent use.
type RotatingFile struct {
	path     string
	maxBytes int64
	keep     int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenRotatingFile opens or creates the log file with mode 0600 in a 0700
// directory.
func OpenRotatingFile(path string, maxBytes int64, keep int) (*RotatingFile, error) {
	if maxBytes <= 0 || keep < 1 {
		return nil, errors.New("diagnostic log: max_bytes and max_files must be positive")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

// Write appends p, rotating first when p would not fit. A single record
// larger than maxBytes is written to a fresh file on its own.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, errors.New("diagnostic log closed")
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	r.f = nil
	// Drop the oldest, shift the rest up by one.
	_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
	for i := r.keep - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", r.path, i)
		if _, err := os.Stat(from); err == nil {
			if err := os.Rename(from, fmt.Sprintf("%s.%d", r.path, i+1)); err != nil {
				return err
			}
		}
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return r.open()
}

// Close closes the file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Options configure NewDaemon.
type Options struct {
	Level    string    // debug, info, warn, error (default info)
	Format   string    // text or json, for Stderr
	Stderr   io.Writer // may be nil
	File     string    // diagnostic log file; empty for none
	MaxBytes int64
	MaxFiles int
}

// NewDaemon returns the daemon's logger: JSON Lines to the rotating file
// and the configured format to standard error, both filtered by one
// LevelVar and both passed through Redact (FR-17.1, FR-17.3). The returned
// closer closes the file.
func NewDaemon(o Options) (*slog.Logger, *slog.LevelVar, io.Closer, error) {
	lv := new(slog.LevelVar)
	if o.Level == "" {
		o.Level = "info"
	}
	if err := SetLevel(lv, o.Level); err != nil {
		return nil, nil, nil, err
	}
	hopts := &slog.HandlerOptions{Level: lv, ReplaceAttr: Redact}
	var handlers []slog.Handler
	if o.Stderr != nil {
		switch strings.ToLower(o.Format) {
		case "", "text":
			handlers = append(handlers, slog.NewTextHandler(o.Stderr, hopts))
		case "json":
			handlers = append(handlers, slog.NewJSONHandler(o.Stderr, hopts))
		default:
			return nil, nil, nil, fmt.Errorf("log format %q: want text or json", o.Format)
		}
	}
	var closer io.Closer = io.NopCloser(nil)
	if o.File != "" {
		rf, err := OpenRotatingFile(o.File, o.MaxBytes, o.MaxFiles)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("diagnostic log %s: %w", o.File, err)
		}
		handlers = append(handlers, slog.NewJSONHandler(rf, hopts))
		closer = rf
	}
	return slog.New(fanHandler(handlers)).With("component", "smcpd"), lv, closer, nil
}

// sensitiveKeys are attribute keys whose values never reach the diagnostic
// log at any level (FR-17.3): secret values, bearer and refresh tokens,
// passwords, tool arguments and tool results. Code must not log them in
// the first place; this is the backstop.
var sensitiveKeys = []string{"password", "passphrase", "token", "secret", "authorization", "cookie", "arguments", "args", "result", "content", "seed", "private_key"}

// Redact is a slog ReplaceAttr that replaces the value of a sensitive
// attribute with "[REDACTED]".
func Redact(_ []string, a slog.Attr) slog.Attr {
	k := strings.ToLower(a.Key)
	for _, s := range sensitiveKeys {
		if k == s || strings.HasSuffix(k, "_"+s) || strings.HasPrefix(k, s+"_") {
			return slog.String(a.Key, "[REDACTED]")
		}
	}
	return a
}

// fanHandler sends each record to every handler.
type fanHandler []slog.Handler

func (f fanHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f fanHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range f {
		if h.Enabled(ctx, r.Level) {
			errs = append(errs, h.Handle(ctx, r.Clone()))
		}
	}
	return errors.Join(errs...)
}

func (f fanHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make(fanHandler, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(as)
	}
	return out
}

func (f fanHandler) WithGroup(name string) slog.Handler {
	out := make(fanHandler, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(name)
	}
	return out
}
