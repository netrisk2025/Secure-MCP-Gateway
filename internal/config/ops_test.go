package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestSchemaVersion(t *testing.T) {
	// FR-13.13: newer refused naming both versions, older refused with a
	// migrate instruction, current accepted, and `config migrate` rewrites
	// an older file. Version 1 is the only real version in release 1.0;
	// as the requirement's verification states, the older case runs
	// against a test-registered version 2 with a migration step.
	reqtest.Verifies(t, "FR-13.13")
	if cfg, err := Parse([]byte(good)); err != nil || cfg.SchemaVersion != 1 {
		t.Fatalf("file without schema_version: %v", err)
	}
	if _, err := Parse([]byte("schema_version = 1\n" + good)); err != nil {
		t.Fatalf("current version: %v", err)
	}
	// Newer: refused before schema validation, so unknown future keys do
	// not hide the version error.
	_, err := Parse([]byte("schema_version = 2\n[future]\nkey = 1\n" + good))
	if !errors.Is(err, ErrSchemaNewer) || !strings.Contains(err.Error(), "schema_version 2") || !strings.Contains(err.Error(), "up to 1") {
		t.Fatalf("newer: %v", err)
	}

	saved, savedM := CurrentSchemaVersion, Migrations
	t.Cleanup(func() { CurrentSchemaVersion, Migrations = saved, savedM })
	CurrentSchemaVersion = 2
	Migrations = []Migration{{From: 1, Rewrite: func(raw []byte) ([]byte, error) {
		return []byte(strings.Replace(string(raw), "[admin]", "# migrated from 1\n[admin]", 1)), nil
	}}}
	_, err = Parse([]byte("schema_version = 1\n" + good))
	if !errors.Is(err, ErrSchemaOlder) || !strings.Contains(err.Error(), "smcpctl config migrate") {
		t.Fatalf("older: %v", err)
	}
	path := filepath.Join(t.TempDir(), "smcp.toml")
	_ = os.WriteFile(path, []byte(good), 0o600) // no key: version 1
	res, err := Migrate(path)
	if err != nil || res.From != 1 || res.To != 2 || res.Backup == "" {
		t.Fatalf("migrate %+v %v", res, err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.SchemaVersion != 2 {
		t.Fatalf("after migrate: %v", err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "# migrated from 1") || !strings.HasPrefix(string(b), "schema_version = 2\n") {
		t.Fatalf("migrated file:\n%s", b)
	}
	if orig, _ := os.ReadFile(res.Backup); string(orig) != good {
		t.Fatal("original not kept")
	}
	if res, err := Migrate(path); err != nil || res.From != 2 || res.Backup != "" {
		t.Fatalf("second migrate %+v %v", res, err)
	}
	// A broken migration leaves the file unchanged.
	_ = os.WriteFile(path, []byte(good), 0o600)
	Migrations = []Migration{{From: 1, Rewrite: func([]byte) ([]byte, error) { return []byte("not toml ["), nil }}}
	if _, err := Migrate(path); err == nil {
		t.Fatal("invalid migration result accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != good {
		t.Fatal("failed migration changed the file")
	}
}

func TestOpsDefaults(t *testing.T) {
	// CP-50 and CP-51 defaults and checks.
	reqtest.Partial(t, "FR-17.2", "FR-17.4")
	dir := t.TempDir()
	path := filepath.Join(dir, "smcp.toml")
	_ = os.WriteFile(path, []byte(good), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Metrics.Enabled || cfg.Metrics.Address != "127.0.0.1:9464" {
		t.Fatalf("metrics %+v", cfg.Metrics)
	}
	if cfg.Log.MaxBytes != 10<<20 || cfg.Log.MaxFiles != 5 || cfg.Log.File != filepath.Join(dir, "state", "log", "smcpd.log") {
		t.Fatalf("log %+v", cfg.Log)
	}
	if cfg.Backup.Dir != filepath.Join(dir, "backups") || cfg.Evidence.ExportDir != "" || cfg.Evidence.ExportInterval.Duration != 10*time.Second {
		t.Fatalf("backup %+v evidence %+v", cfg.Backup, cfg.Evidence)
	}
	for name, extra := range map[string]string{
		"metrics not loopback":  "[metrics]\nenabled = true\naddress = \"0.0.0.0:9464\"\n",
		"metrics on listener":   "[metrics]\nenabled = true\naddress = \"127.0.0.1:8443\"\n",
		"export interval > 50s": "[evidence]\nexport_dir = \"x\"\nexport_interval = \"55s\"\n",
		"log files 0":           "[log]\nmax_files = 0\n",
	} {
		if _, err := Parse([]byte(withBefore(extra))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDiffAndReloadableKeys(t *testing.T) {
	// CP-50 classification behind FR-17.9.
	reqtest.Partial(t, "FR-17.9")
	a, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(withBefore("[limits]\ntool_queue = 3\n[listener]\naddress = \"127.0.0.1:9443\"\n[log]\nlevel = \"debug\"\n")))
	if err != nil {
		t.Fatal(err)
	}
	b.Servers[0].Command = "/opt/other"
	b.Clients = append(b.Clients, Client{ClientID: "new", Principal: "cc"})
	d, err := Diff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"client.new", "client.new.client_id", "client.new.principal", "listener.address", "log.level", "server.fs.command", "limits.tool_queue"}
	for _, k := range want {
		found := false
		for _, g := range d {
			found = found || g == k
		}
		if !found {
			t.Errorf("diff lacks %s: %v", k, d)
		}
	}
	for k, reloadable := range map[string]bool{"log.level": true, "limits.principal_calls_per_minute": true, "limits.principal_call_burst": true,
		"limits.tool_queue": false, "client.new": false, "server.fs.enabled": false,
		"listener.address": false, "state.dir": false, "profile.mode": false, "server.fs.command": false, "log.format": false} {
		if ReloadableKey(k) != reloadable {
			t.Errorf("ReloadableKey(%s) = %v", k, !reloadable)
		}
	}
	if d, _ := Diff(a, a); len(d) != 0 {
		t.Fatalf("self diff %v", d)
	}
}
