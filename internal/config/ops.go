package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// CurrentSchemaVersion is the highest configuration schema_version this
// release reads (FR-13.13). A file without schema_version is read as
// version 1, the first versioned format, so files written before the key
// existed keep working.
var CurrentSchemaVersion = 1

// Migration rewrites a configuration file of version From to From+1. The
// list is empty while only version 1 exists; a release that changes the
// format appends the step. Tests register their own.
type Migration struct {
	From    int
	Rewrite func(raw []byte) ([]byte, error)
}

// Migrations are applied in order by Migrate.
var Migrations []Migration

// ErrSchemaNewer and ErrSchemaOlder classify a schema_version refusal.
var (
	ErrSchemaNewer = errors.New("configuration schema_version is newer than this release supports")
	ErrSchemaOlder = errors.New("configuration schema_version is older than this release reads")
)

// Metrics configures the loopback Prometheus endpoint (FR-17.4, CP-51).
type Metrics struct {
	Enabled bool   `toml:"enabled" json:"enabled"`
	Address string `toml:"address" json:"address"`
}

// Evidence configures evidence export (FR-7.14, X-09).
type Evidence struct {
	// ExportDir receives a copy of each closed journal segment and the
	// anchor. Empty disables export.
	ExportDir      string   `toml:"export_dir" json:"export_dir"`
	ExportInterval Duration `toml:"export_interval" json:"export_interval"`
	// QuotaBytes is the Evidence Journal's storage quota (CP-26, default
	// 10 GiB); health warns at 80% (FR-9.15).
	QuotaBytes int64 `toml:"quota_bytes" json:"quota_bytes"`
}

// DefaultEvidenceQuota is CP-26.
const DefaultEvidenceQuota = 10 << 30

// Backup configures where `smcpctl backup` writes archives (D-15).
type Backup struct {
	Dir string `toml:"dir" json:"dir"`
	// Interval schedules backups (FR-9.16); zero runs them on demand only.
	// A scheduled backup is encrypted to Recipients (age public keys) or
	// with the passphrase read from PassphraseFile.
	Interval       Duration `toml:"interval" json:"interval"`
	PassphraseFile string   `toml:"passphrase_file" json:"passphrase_file"`
	Recipients     []string `toml:"recipients" json:"recipients"`
}

// Defaults of the operations sections (CP-50, CP-51).
const (
	DefaultMetricsAddress = "127.0.0.1:9464"
	DefaultLogMaxBytes    = 10 << 20
	DefaultLogMaxFiles    = 5
	DefaultExportInterval = 10 * time.Second
)

func schemaVersionOf(doc map[string]any) (int, error) {
	v, ok := doc["schema_version"]
	if !ok {
		return 1, nil
	}
	n, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("schema_version must be an integer")
	}
	return int(n), nil
}

func checkSchemaVersion(doc map[string]any) error {
	v, err := schemaVersionOf(doc)
	if err != nil {
		return err
	}
	switch {
	case v > CurrentSchemaVersion:
		return fmt.Errorf("%w: the file has schema_version %d and this release supports up to %d; upgrade the Gateway or restore the previous configuration", ErrSchemaNewer, v, CurrentSchemaVersion)
	case v < CurrentSchemaVersion:
		return fmt.Errorf("%w: the file has schema_version %d and this release reads %d; run `smcpctl config migrate` to rewrite it", ErrSchemaOlder, v, CurrentSchemaVersion)
	}
	return nil
}

func (c *Config) applyOpsDefaults() error {
	if c.SchemaVersion == 0 {
		c.SchemaVersion = 1
	}
	if c.Metrics.Address == "" {
		c.Metrics.Address = DefaultMetricsAddress
	}
	if c.Log.MaxBytes == 0 {
		c.Log.MaxBytes = DefaultLogMaxBytes
	}
	if c.Log.MaxFiles == 0 {
		c.Log.MaxFiles = DefaultLogMaxFiles
	}
	if c.Evidence.QuotaBytes == 0 {
		c.Evidence.QuotaBytes = DefaultEvidenceQuota
	}
	if c.Evidence.ExportInterval.Duration == 0 {
		c.Evidence.ExportInterval.Duration = DefaultExportInterval
	}
	if c.Evidence.ExportInterval.Duration < time.Second || c.Evidence.ExportInterval.Duration > 50*time.Second {
		// FR-7.14 bounds the copy to 60 s after segment closure.
		return errors.New("evidence.export_interval must be between 1s and 50s")
	}
	if c.Backup.Dir == "" {
		c.Backup.Dir = "backups"
	}
	if iv := c.Backup.Interval.Duration; iv != 0 {
		if iv < time.Second {
			return errors.New("backup.interval must be at least 1s")
		}
		if c.Backup.PassphraseFile == "" && len(c.Backup.Recipients) == 0 {
			return errors.New("backup.interval needs backup.passphrase_file or backup.recipients: scheduled backups are encrypted (FR-17.6)")
		}
	}
	if c.Metrics.Enabled {
		for _, other := range []string{c.Listener.Address, c.AdminListener.Address} {
			if sameHostPort(c.Metrics.Address, other) {
				return fmt.Errorf("metrics.address %s must differ from the listener addresses", c.Metrics.Address)
			}
		}
	}
	return nil
}

// resolveOpsPaths runs after the state directory is resolved.
func (c *Config) resolveOpsPaths(res func(*string)) {
	if c.Log.File == "" {
		c.Log.File = filepath.Join(c.State.Dir, "log", "smcpd.log")
	} else {
		res(&c.Log.File)
	}
	res(&c.Evidence.ExportDir)
	res(&c.Backup.Dir)
	if c.Backup.PassphraseFile != "" {
		res(&c.Backup.PassphraseFile)
	}
}

var schemaVersionLine = regexp.MustCompile(`(?m)^schema_version\s*=\s*[0-9]+[ \t]*(#.*)?$`)

// SetSchemaVersion rewrites or inserts the top-level schema_version line.
func SetSchemaVersion(raw []byte, v int) []byte {
	line := []byte("schema_version = " + strconv.Itoa(v))
	if schemaVersionLine.Match(raw) {
		return schemaVersionLine.ReplaceAll(raw, line)
	}
	// Top-level keys must precede the first table header.
	return append(append(line, '\n'), raw...)
}

// MigrateResult reports a migration.
type MigrateResult struct {
	From, To int
	Backup   string // copy of the original file; "" when nothing changed
}

// Migrate rewrites the configuration file at path to CurrentSchemaVersion
// (`smcpctl config migrate`, FR-13.13). The original is kept as
// <path>.v<from>.bak. A file at the current version is left unchanged; a
// newer file is refused.
func Migrate(path string) (MigrateResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return MigrateResult{}, err
	}
	var doc map[string]any
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return MigrateResult{}, fmt.Errorf("parse: %w", err)
	}
	from, err := schemaVersionOf(doc)
	if err != nil {
		return MigrateResult{}, err
	}
	res := MigrateResult{From: from, To: from}
	if from > CurrentSchemaVersion {
		return res, fmt.Errorf("%w: the file has schema_version %d and this release supports up to %d", ErrSchemaNewer, from, CurrentSchemaVersion)
	}
	if from == CurrentSchemaVersion {
		return res, nil
	}
	out := raw
	for v := from; v < CurrentSchemaVersion; v++ {
		step := -1
		for i, m := range Migrations {
			if m.From == v {
				step = i
			}
		}
		if step < 0 {
			return res, fmt.Errorf("no migration from schema_version %d", v)
		}
		if out, err = Migrations[step].Rewrite(out); err != nil {
			return res, fmt.Errorf("migration from schema_version %d: %w", v, err)
		}
		out = SetSchemaVersion(out, v+1)
	}
	if _, err := Parse(out); err != nil {
		return res, fmt.Errorf("migrated configuration is invalid: %w", err)
	}
	res.Backup = fmt.Sprintf("%s.v%d.bak", path, from)
	if err := os.WriteFile(res.Backup, raw, 0o600); err != nil {
		return res, err
	}
	if !bytes.Equal(out, raw) {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, out, 0o600); err != nil {
			return res, err
		}
		if err := os.Rename(tmp, path); err != nil {
			return res, err
		}
	}
	res.To = CurrentSchemaVersion
	return res, nil
}

// ReloadableKey reports whether a changed configuration key can be applied
// by a reload without a restart (CP-50). Keys are dotted paths as produced
// by Diff, for example "limits.tool_queue" or "server.ref.enabled".
func ReloadableKey(key string) bool {
	for _, p := range reloadablePrefixes {
		if p.MatchString(key) {
			return true
		}
	}
	return false
}

var reloadablePrefixes = []*regexp.Regexp{
	regexp.MustCompile(`^log\.level$`),
	regexp.MustCompile(`^limits\.principal_calls_per_minute$`),
	regexp.MustCompile(`^limits\.principal_call_burst$`),
}
