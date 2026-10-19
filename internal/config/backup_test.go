package config

import (
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// TestBackupScheduleSettings: [backup] interval schedules backups only
// with an encryption source, and not more often than once a second
// (FR-9.16; the scheduled run is internal/e2e TestScheduledAndOnDemandBackups).
func TestBackupScheduleSettings(t *testing.T) {
	reqtest.Partial(t, "FR-9.16")
	for name, c := range map[string]struct{ toml, err string }{
		"no encryption": {"[backup]\ninterval = \"24h\"\n", "passphrase_file or backup.recipients"},
		"too often":     {"[backup]\ninterval = \"500ms\"\nrecipients = [\"age1x\"]\n", "at least 1s"},
		"recipients":    {"[backup]\ninterval = \"24h\"\nrecipients = [\"age1x\"]\n", ""},
		"passphrase":    {"[backup]\ninterval = \"1h\"\npassphrase_file = \"pass\"\n", ""},
		"on demand":     {"[backup]\ndir = \"b\"\n", ""},
	} {
		cfg, err := Parse([]byte(withBefore(c.toml)))
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: %v, want %q", name, err, c.err)
		case name == "recipients" && cfg.Backup.Interval.Duration != 24*time.Hour:
			t.Errorf("interval %v", cfg.Backup.Interval.Duration)
		}
	}
}
