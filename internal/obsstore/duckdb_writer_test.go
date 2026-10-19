//go:build cgo

package obsstore

import (
	"database/sql"
	"testing"
)

// TestBatchesUseSingleThreadedInstance: store batches are copied to Parquet
// by a single-threaded DuckDB instance, so a batch runs entirely on the
// store writer's thread (at its lowered priority) and never waits for, or
// runs on, the query instance's worker thread (FR-11.4). Batches written
// this way read back through the query instance.
func TestBatchesUseSingleThreadedInstance(t *testing.T) {
	st, err := Open(Options{Dir: t.TempDir(), Backend: "duckdb", Tables: []Table{recordsV1}, MemoryLimit: 512 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := st.(*duckStore)
	setting := func(db *sql.DB, name string) string {
		var v string
		if err := db.QueryRow("SELECT current_setting('" + name + "')::VARCHAR").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if got := setting(s.w, "threads"); got != "1" {
		t.Fatalf("writer instance threads %s, want 1", got)
	}
	if got := setting(s.db, "threads"); got != "2" {
		t.Fatalf("query instance threads %s, want 2", got)
	}
	rows := fixture(40, 3)
	if err := st.Append("records", rows); err != nil {
		t.Fatal(err)
	}
	n := 0
	if err := st.Scan("records", Filter{}, func(Row) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n != len(rows) {
		t.Fatalf("read back %d rows, want %d", n, len(rows))
	}
}
