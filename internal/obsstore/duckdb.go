//go:build cgo

package obsstore

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/duckdb/duckdb-go/v2" // official DuckDB driver (cgo)
)

const duckdbAvailable = true

// duckStore writes one zstd-compressed Parquet file per flushed batch and
// day partition and answers queries with DuckDB over those files. DuckDB
// runs in memory; the Parquet files are the store. Extensions are never
// installed or loaded from the network (FR-12.2): JSON and Parquet support
// are built into the driver's library.
//
// Batches are written by a second in-memory DuckDB instance with a single
// thread (w), which runs each COPY entirely on the calling thread: the
// store writer's thread, at lowered priority (internal/analytics). Through
// the two-threaded query instance (db) a batch's COPY ran on two threads
// that, on a host whose processors are all busy, waited for each other:
// each batch took about twice its idle CPU time, five batches a second per
// table (FR-9.5), most of observation's CPU time on the 4-CPU CI runners
// and part of what put it over its FR-11.4 budget.
type duckStore struct {
	*base
	db      *sql.DB // queries and research exports
	w       *sql.DB // store batches (Append)
	staging string
}

// writerMemory is the memory limit of the single-threaded instance that
// writes batches (at most 1,000 rows each, FR-9.5); it comes out of
// Options.MemoryLimit, so both instances together keep CP-33's bound.
const writerMemory = 64 << 20

func openDuckDB(o Options) (Store, error) {
	const opts = "autoinstall_known_extensions=false&autoload_known_extensions=false"
	queryMem, writeMem := o.MemoryLimit, int64(writerMemory)
	if o.MemoryLimit > 0 {
		writeMem = min(writeMem, o.MemoryLimit/4)
		queryMem = o.MemoryLimit - writeMem
	}
	open := func(threads int, mem int64) (*sql.DB, error) {
		dsn := "?threads=" + strconv.Itoa(threads) + "&" + opts
		if mem > 0 {
			dsn += "&memory_limit=" + strconv.FormatInt(mem>>20, 10) + "MB"
		}
		db, err := sql.Open("duckdb", dsn)
		if err != nil {
			return nil, fmt.Errorf("duckdb: %w", err)
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, fmt.Errorf("duckdb: %w", err)
		}
		return db, nil
	}
	db, err := open(2, queryMem)
	if err != nil {
		return nil, err
	}
	w, err := open(1, writeMem)
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &duckStore{base: newBase(o), db: db, w: w, staging: filepath.Join(o.Dir, ".staging")}
	if err := os.MkdirAll(s.staging, 0o700); err != nil {
		s.Close()
		return nil, err
	}
	// Leftover staging files from a crash are partial batches that were
	// never published; remove them.
	if m, _ := filepath.Glob(filepath.Join(s.staging, "*")); len(m) > 0 {
		for _, p := range m {
			os.Remove(p)
		}
	}
	return s, nil
}

func (s *duckStore) Backend() string { return "duckdb" }

func sqlString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func quoteIdent(s string) string { return `"` + s + `"` }

func columnsSpec(cols []Column) string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		parts = append(parts, sqlString(c.Name)+":"+sqlString(c.Type))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// WriteParquet implements ParquetWriter.
func (s *duckStore) WriteParquet(cols []Column, jsonlPath, parquetPath string) error {
	return writeParquet(s.db, cols, jsonlPath, parquetPath)
}

// writeParquet copies a JSON Lines file with the columns cols to a
// zstd-compressed Parquet file with db.
func writeParquet(db *sql.DB, cols []Column, jsonlPath, parquetPath string) error {
	for _, c := range cols {
		if !validName(c.Name) {
			return fmt.Errorf("%w: %q", ErrBadColumn, c.Name)
		}
	}
	sel := make([]string, 0, len(cols))
	for _, c := range cols {
		sel = append(sel, quoteIdent(c.Name))
	}
	// Identifiers are validated column names; paths are quoted literals.
	q := fmt.Sprintf("COPY (SELECT %s FROM read_json(%s, format='newline_delimited', columns=%s)) TO %s (FORMAT parquet, COMPRESSION zstd)", //nolint:gosec // G201: validated identifiers and quoted literals only
		strings.Join(sel, ","), sqlString(jsonlPath), columnsSpec(cols), sqlString(parquetPath))
	if _, err := db.Exec(q); err != nil {
		return fmt.Errorf("duckdb: write parquet: %w", err)
	}
	return os.Chmod(parquetPath, 0o600)
}

func (s *duckStore) Append(table string, rows []Row) error {
	t, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownTable, table)
	}
	norm := make([]Row, 0, len(rows))
	for _, r := range rows {
		n, err := s.normalize(t, r)
		if err != nil {
			return err
		}
		norm = append(norm, n)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for day, rs := range byDay(norm) {
		dir := s.partDir(table, day)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		name := s.nextName()
		tmp := filepath.Join(s.staging, name+".jsonl")
		// The staging file is read once by the COPY below and removed
		// (and removed at open after a crash), so it is not synced: an
		// fsync per batch and table only competed with the journal's
		// commits for the disk.
		if err := writeJSONL(tmp, t, rs, false); err != nil {
			return err
		}
		// Write under a temporary name and rename, so that a reader never
		// sees a partial Parquet file.
		part := filepath.Join(dir, name+".parquet")
		err := writeParquet(s.w, t.Columns, tmp, part+".tmp")
		os.Remove(tmp)
		if err != nil {
			os.Remove(part + ".tmp")
			return err
		}
		if err := os.Rename(part+".tmp", part); err != nil {
			return err
		}
	}
	s.countRows(table, len(norm))
	return nil
}

// source returns the read_parquet expression over the files in range and
// the set of columns present in them; ok is false when there are no files.
func (s *duckStore) source(table string, f Filter) (string, map[string]bool, bool, error) {
	files, err := s.files(table, ".parquet", f)
	if err != nil || len(files) == 0 {
		return "", nil, false, err
	}
	lits := make([]string, len(files))
	for i, p := range files {
		lits[i] = sqlString(p)
	}
	src := "read_parquet([" + strings.Join(lits, ",") + "], union_by_name=true)"
	rows, err := s.db.Query("DESCRIBE SELECT * FROM " + src) //nolint:gosec // G202: src holds quoted file-path literals only
	if err != nil {
		return "", nil, false, fmt.Errorf("duckdb: %w", err)
	}
	defer rows.Close()
	present := map[string]bool{}
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return "", nil, false, err
		}
		if name, ok := vals[0].(string); ok {
			present[name] = true
		}
	}
	return src, present, true, rows.Err()
}

// where renders the filter as SQL with parameters. A column absent from
// every file reads as NULL, which matches only the empty string.
func where(f Filter, present map[string]bool) (string, []any, bool) {
	var conds []string
	var args []any
	if !f.From.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, f.From.UTC())
	}
	if !f.To.IsZero() {
		conds = append(conds, "ts < ?")
		args = append(args, f.To.UTC())
	}
	cols := make([]string, 0, len(f.Equals))
	for c := range f.Equals {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	for _, c := range cols {
		vals := f.Equals[c]
		if !present[c] {
			matchEmpty := false
			for _, v := range vals {
				if v == "" {
					matchEmpty = true
				}
			}
			if !matchEmpty {
				return "", nil, false
			}
			continue
		}
		if len(vals) == 0 {
			return "", nil, false
		}
		ph := strings.TrimSuffix(strings.Repeat("?,", len(vals)), ",")
		conds = append(conds, fmt.Sprintf("coalesce(CAST(%s AS VARCHAR), '') IN (%s)", quoteIdent(c), ph))
		for _, v := range vals {
			args = append(args, v)
		}
	}
	if len(conds) == 0 {
		return "", args, true
	}
	return " WHERE " + strings.Join(conds, " AND "), args, true
}

func (s *duckStore) Scan(table string, f Filter, fn func(Row) error) error {
	t, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownTable, table)
	}
	for c := range f.Equals {
		if !validName(c) {
			return fmt.Errorf("%w: %q", ErrBadColumn, c)
		}
	}
	src, present, ok, err := s.source(table, f)
	if err != nil || !ok {
		return err
	}
	w, args, ok := where(f, present)
	if !ok {
		return nil
	}
	q := "SELECT * FROM " + src + w + " ORDER BY ts" //nolint:gosec // G202: quoted paths, validated identifiers, values as parameters
	if f.Limit > 0 {
		q += " LIMIT " + strconv.Itoa(f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return fmt.Errorf("duckdb: %w", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		r := Row{}
		for i, c := range cols {
			if vals[i] == nil {
				continue
			}
			if col, ok := t.column(c); ok {
				v, err := convert(col, vals[i])
				if err != nil {
					return fmt.Errorf("%s: %w", c, err)
				}
				r[c] = v
			} else {
				r[c] = vals[i]
			}
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *duckStore) Aggregate(q AggQuery) ([]AggRow, error) {
	if _, err := validateAgg(s.tables, &q); err != nil {
		return nil, err
	}
	src, present, ok, err := s.source(q.Table, q.Filter)
	if err != nil || !ok || !present[q.Feature] {
		return []AggRow{}, err
	}
	w, args, ok := where(q.Filter, present)
	if !ok {
		return []AggRow{}, nil
	}
	if w == "" {
		w = " WHERE "
	} else {
		w += " AND "
	}
	w += quoteIdent(q.Feature) + " IS NOT NULL"

	var inner, groups, sel []string
	inner = append(inner, "CAST("+quoteIdent(q.Feature)+" AS DOUBLE) AS x", "ts")
	for i, g := range q.GroupBy {
		alias := "g" + strconv.Itoa(i)
		if present[g] {
			inner = append(inner, quoteIdent(g)+" AS "+alias)
		} else {
			inner = append(inner, "NULL AS "+alias)
		}
		groups = append(groups, alias)
	}
	sel = append(sel, groups...)
	if q.Bucket > 0 {
		b := strconv.FormatInt(q.Bucket.Microseconds(), 10)
		sel = append(sel, "(epoch_us(ts) // "+b+") * "+b+" AS bucket_us")
		groups = append(groups, "bucket_us")
	}
	sel = append(sel, "count(x)", "avg(x)", "coalesce(var_samp(x), 0)", "min(x)", "max(x)")
	for _, p := range q.Quantiles {
		sel = append(sel, "quantile_cont(x, "+strconv.FormatFloat(p, 'g', -1, 64)+")")
	}
	if len(q.Histogram) > 0 {
		hb := q.Histogram
		bound := func(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }
		sel = append(sel, "count(*) FILTER (WHERE x <= "+bound(hb[0])+")")
		for i := 1; i < len(hb); i++ {
			sel = append(sel, "count(*) FILTER (WHERE x > "+bound(hb[i-1])+" AND x <= "+bound(hb[i])+")")
		}
		sel = append(sel, "count(*) FILTER (WHERE x > "+bound(hb[len(hb)-1])+")")
	}
	stmt := "SELECT " + strings.Join(sel, ", ") + " FROM (SELECT " + strings.Join(inner, ", ") + " FROM " + src + w + ") t" //nolint:gosec // G202: validated identifiers, numeric literals and quoted paths; values as parameters
	if len(groups) > 0 {
		stmt += " GROUP BY " + strings.Join(groups, ", ")
	}
	rows, err := s.db.Query(stmt, args...)
	if err != nil {
		return nil, fmt.Errorf("duckdb: %w", err)
	}
	defer rows.Close()
	var out []AggRow
	for rows.Next() {
		n := len(q.GroupBy)
		vals := make([]any, len(sel))
		ptrs := make([]any, len(sel))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := AggRow{Group: map[string]string{}}
		for i, g := range q.GroupBy {
			r.Group[g] = groupString(vals[i])
		}
		i := n
		if q.Bucket > 0 {
			us, _ := vals[i].(int64)
			b := time.UnixMicro(us).UTC()
			r.Bucket = &b
			i++
		}
		r.Count, _ = vals[i].(int64)
		r.Mean, _ = toFloat(vals[i+1])
		r.Variance, _ = toFloat(vals[i+2])
		r.Min, _ = toFloat(vals[i+3])
		r.Max, _ = toFloat(vals[i+4])
		i += 5
		for range q.Quantiles {
			v, _ := toFloat(vals[i])
			r.Quantiles = append(r.Quantiles, v)
			i++
		}
		if len(q.Histogram) > 0 {
			r.Histogram = make([]int64, len(q.Histogram)+1)
			for k := range r.Histogram {
				r.Histogram[k], _ = vals[i].(int64)
				i++
			}
		}
		if r.Count < 2 {
			r.Variance = 0
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortAgg(out)
	return out, nil
}

func (s *duckStore) Retain(now time.Time, keep time.Duration) ([]string, error) {
	return s.retain(now, keep)
}

func (s *duckStore) Stats() (Stats, error) { return s.stats("duckdb") }

func (s *duckStore) Close() error {
	werr := s.w.Close()
	if err := s.db.Close(); err != nil {
		return err
	}
	return werr
}
