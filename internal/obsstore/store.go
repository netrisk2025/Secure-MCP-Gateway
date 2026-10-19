// Package obsstore is the Observation Store (E-27): append-oriented,
// day-partitioned storage of observation records, timing spans, system
// meta-metrics and scoring records (D-09, D-13), with the aggregate queries
// of FR-9.9.
//
// Two backends implement Store. "duckdb" writes one Parquet file per flushed
// batch under <dir>/<table>/day=YYYY-MM-DD/ and queries them through DuckDB
// (official Go driver, cgo). "jsonl" writes JSON Lines files in the same
// layout and evaluates queries in Go; it is used when the binary is built
// without cgo (release archives are CGO_ENABLED=0) or when configured.
// Both give the same results for the same data.
package obsstore

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Column types.
const (
	Varchar   = "VARCHAR"
	BigInt    = "BIGINT"
	Double    = "DOUBLE"
	Timestamp = "TIMESTAMP"
)

// Column is one table column.
type Column struct {
	Name string
	Type string
}

// Table is a table schema. Every table has the column "ts" (TIMESTAMP, UTC)
// that selects its day partition.
type Table struct {
	Name    string
	Columns []Column
}

func (t Table) column(name string) (Column, bool) {
	for _, c := range t.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return Column{}, false
}

// Row is one row keyed by column name. Values are string, int64, float64,
// bool, time.Time or nil; any other value of a VARCHAR column is stored as
// its JSON text.
type Row map[string]any

// Filter selects rows: From inclusive, To exclusive (zero means unbounded),
// and for each Equals column one of the listed values.
type Filter struct {
	From, To time.Time
	Equals   map[string][]string
	Limit    int // 0: no limit
}

// AggQuery is an aggregate query over one numeric column (FR-9.9).
type AggQuery struct {
	Table     string // default "records"
	Feature   string
	GroupBy   []string
	Bucket    time.Duration // 0: one bucket for the whole range
	Filter    Filter
	Quantiles []float64 // linear interpolation between order statistics
	// Histogram holds ascending upper bounds b0 < b1 < ... < bn; the result
	// has n+2 counts for (-inf,b0], (b0,b1], ..., (bn,+inf).
	Histogram []float64
}

// AggRow is one group of an aggregate result. Variance is the sample
// variance (0 when Count < 2).
type AggRow struct {
	Group     map[string]string `json:"group"`
	Bucket    *time.Time        `json:"bucket,omitempty"`
	Count     int64             `json:"count"`
	Mean      float64           `json:"mean"`
	Variance  float64           `json:"variance"`
	Min       float64           `json:"min"`
	Max       float64           `json:"max"`
	Quantiles []float64         `json:"quantiles,omitempty"`
	Histogram []int64           `json:"histogram,omitempty"`
}

// Stats describes the store's files.
type Stats struct {
	Backend string              `json:"backend"`
	Dir     string              `json:"dir"`
	Bytes   int64               `json:"bytes"`
	Files   int                 `json:"files"`
	Days    map[string][]string `json:"days"` // table -> partitions
	Rows    map[string]int64    `json:"rows_written"`
}

// Store is the Observation Store interface.
type Store interface {
	Backend() string
	Table(name string) (Table, bool)
	Append(table string, rows []Row) error
	Scan(table string, f Filter, fn func(Row) error) error
	Aggregate(q AggQuery) ([]AggRow, error)
	// Retain deletes day partitions older than keep before now and returns
	// "<table>/day=<date>" for each.
	Retain(now time.Time, keep time.Duration) ([]string, error)
	Stats() (Stats, error)
	Close() error
}

// ParquetWriter is implemented by backends that can write Parquet.
type ParquetWriter interface {
	// WriteParquet converts a JSON Lines file whose objects use the given
	// columns into a Parquet file.
	WriteParquet(cols []Column, jsonlPath, parquetPath string) error
}

// Errors.
var (
	ErrUnavailable  = errors.New("obsstore: backend unavailable in this build")
	ErrUnknownTable = errors.New("obsstore: unknown table")
	ErrBadColumn    = errors.New("obsstore: invalid column")
)

// Options open a store.
type Options struct {
	Dir     string
	Backend string // "auto" (duckdb when available), "duckdb" or "jsonl"
	Tables  []Table
	// MemoryLimit bounds DuckDB memory (CP-33: 512 MiB); 0 keeps the default.
	MemoryLimit int64
}

// DuckDBAvailable reports whether this build includes the DuckDB backend.
func DuckDBAvailable() bool { return duckdbAvailable }

// Open opens or creates a store.
func Open(o Options) (Store, error) {
	if o.Dir == "" {
		return nil, errors.New("obsstore: no directory")
	}
	for _, t := range o.Tables {
		if !validName(t.Name) {
			return nil, fmt.Errorf("%w: table %q", ErrBadColumn, t.Name)
		}
		if c, ok := t.column("ts"); !ok || c.Type != Timestamp {
			return nil, fmt.Errorf("obsstore: table %s has no ts TIMESTAMP column", t.Name)
		}
		for _, c := range t.Columns {
			if !validName(c.Name) {
				return nil, fmt.Errorf("%w: %q", ErrBadColumn, c.Name)
			}
		}
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(o.Dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the search bit; owner only
		return nil, err
	}
	switch o.Backend {
	case "", "auto":
		if duckdbAvailable {
			return openDuckDB(o)
		}
		return openJSONL(o)
	case "duckdb":
		return openDuckDB(o)
	case "jsonl":
		return openJSONL(o)
	}
	return nil, fmt.Errorf("obsstore: unknown backend %q", o.Backend)
}

var nameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func validName(s string) bool { return nameRE.MatchString(s) }

// DayOf is the UTC day partition of t.
func DayOf(t time.Time) string { return t.UTC().Format("2006-01-02") }

// base holds what both backends share: schemas, the directory layout and
// file bookkeeping.
type base struct {
	dir    string
	tables map[string]Table
	cols   map[string]map[string]Column // table -> column name -> column
	mu     sync.Mutex                   // serializes appends and retention
	seq    atomic.Uint64
	rows   sync.Map // table -> *atomic.Int64
}

func newBase(o Options) *base {
	b := &base{dir: o.Dir, tables: map[string]Table{}, cols: map[string]map[string]Column{}}
	for _, t := range o.Tables {
		b.tables[t.Name] = t
		b.cols[t.Name] = make(map[string]Column, len(t.Columns))
		for _, c := range t.Columns {
			b.cols[t.Name][c.Name] = c
		}
		b.rows.Store(t.Name, new(atomic.Int64))
	}
	return b
}

func (b *base) Table(name string) (Table, bool) { t, ok := b.tables[name]; return t, ok }

func (b *base) countRows(table string, n int) {
	if v, ok := b.rows.Load(table); ok {
		v.(*atomic.Int64).Add(int64(n))
	}
}

// normalize converts a row to the column types. Unknown columns are
// refused so that every stored column is a declared one.
func (b *base) normalize(t Table, r Row) (Row, error) {
	out := make(Row, len(r))
	cols := b.cols[t.Name]
	for k, v := range r {
		c, ok := cols[k]
		if !ok {
			return nil, fmt.Errorf("%w: %s.%s not declared", ErrBadColumn, t.Name, k)
		}
		nv, err := convert(c, v)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", t.Name, k, err)
		}
		if nv != nil {
			out[k] = nv
		}
	}
	if _, ok := out["ts"].(time.Time); !ok {
		return nil, fmt.Errorf("%s: row without ts", t.Name)
	}
	return out, nil
}

func convert(c Column, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch c.Type {
	case Timestamp:
		switch x := v.(type) {
		case time.Time:
			return x.UTC().Truncate(time.Microsecond), nil
		case string:
			return parseTS(x)
		}
	case BigInt:
		switch x := v.(type) {
		case int:
			return int64(x), nil
		case int64:
			return x, nil
		case int32:
			return int64(x), nil
		case uint64:
			if x > math.MaxInt64 {
				return nil, fmt.Errorf("integer overflow")
			}
			return int64(x), nil
		case float64:
			if x != math.Trunc(x) || math.IsInf(x, 0) || math.IsNaN(x) {
				return nil, fmt.Errorf("not an integer: %v", x)
			}
			return int64(x), nil
		case json.Number:
			return x.Int64()
		case bool:
			if x {
				return int64(1), nil
			}
			return int64(0), nil
		}
	case Double:
		switch x := v.(type) {
		case float64:
			if math.IsInf(x, 0) || math.IsNaN(x) {
				return nil, nil
			}
			return x, nil
		case float32:
			return float64(x), nil
		case int:
			return float64(x), nil
		case int64:
			return float64(x), nil
		case json.Number:
			return x.Float64()
		}
	case Varchar:
		switch x := v.(type) {
		case string:
			return x, nil
		case bool:
			return strconv.FormatBool(x), nil
		default:
			raw, err := json.Marshal(x)
			if err != nil {
				return nil, err
			}
			return string(raw), nil
		}
	}
	return nil, fmt.Errorf("value %T does not fit %s", v, c.Type)
}

// tsLayout is the timestamp text both backends store: UTC, microseconds,
// a format DuckDB parses as TIMESTAMP.
const tsLayout = "2006-01-02 15:04:05.000000"

func parseTS(s string) (time.Time, error) {
	if t, err := time.Parse(tsLayout, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC().Truncate(time.Microsecond), nil
}

// jsonValue renders a normalized value for a JSON Lines file.
func jsonValue(v any) any {
	if t, ok := v.(time.Time); ok {
		return t.UTC().Format(tsLayout)
	}
	return v
}

// byDay splits normalized rows by their day partition.
func byDay(rows []Row) map[string][]Row {
	out := map[string][]Row{}
	for _, r := range rows {
		d := DayOf(r["ts"].(time.Time))
		out[d] = append(out[d], r)
	}
	return out
}

func (b *base) partDir(table, day string) string {
	return filepath.Join(b.dir, table, "day="+day)
}

// nextName returns a unique, time-ordered file stem.
func (b *base) nextName() string {
	return fmt.Sprintf("part-%d-%06d", time.Now().UTC().UnixNano(), b.seq.Add(1))
}

// writeJSONL writes rows to path (mode 0600) using the column order of t,
// and with durable set syncs the file before it returns.
func writeJSONL(path string, t Table, rows []Row, durable bool) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	var line []byte
	for _, r := range rows {
		var err error
		if line, err = appendRowJSON(line[:0], t, r); err != nil {
			f.Close()
			return err
		}
		if _, err := w.Write(line); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if durable {
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

// days lists the day partitions of a table within the filter range.
func (b *base) days(table string, f Filter) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(b.dir, table))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		d, ok := strings.CutPrefix(e.Name(), "day=")
		if !ok || !e.IsDir() {
			continue
		}
		if !f.From.IsZero() && d < DayOf(f.From) {
			continue
		}
		if !f.To.IsZero() && d > DayOf(f.To) {
			continue
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// files lists the data files with the given extension within the range.
func (b *base) files(table, ext string, f Filter) ([]string, error) {
	days, err := b.days(table, f)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range days {
		m, err := filepath.Glob(filepath.Join(b.partDir(table, d), "*"+ext))
		if err != nil {
			return nil, err
		}
		sort.Strings(m)
		out = append(out, m...)
	}
	return out, nil
}

func (b *base) retain(now time.Time, keep time.Duration) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// A partition expires when its whole day ended before now - keep.
	cut := now.Add(-keep).UTC()
	var removed []string
	for name := range b.tables {
		days, err := b.days(name, Filter{})
		if err != nil {
			return removed, err
		}
		for _, d := range days {
			start, err := time.Parse("2006-01-02", d)
			if err != nil {
				continue
			}
			if !start.Add(24 * time.Hour).After(cut) {
				if err := os.RemoveAll(b.partDir(name, d)); err != nil {
					return removed, err
				}
				removed = append(removed, name+"/day="+d)
			}
		}
	}
	sort.Strings(removed)
	return removed, nil
}

func (b *base) stats(backend string) (Stats, error) {
	s := Stats{Backend: backend, Dir: b.dir, Days: map[string][]string{}, Rows: map[string]int64{}}
	for name := range b.tables {
		days, err := b.days(name, Filter{})
		if err != nil {
			return s, err
		}
		s.Days[name] = days
		if v, ok := b.rows.Load(name); ok {
			s.Rows[name] = v.(*atomic.Int64).Load()
		}
	}
	err := filepath.WalkDir(b.dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				s.Bytes += info.Size()
				s.Files++
			}
		}
		return nil
	})
	return s, err
}

// matches applies a filter to a normalized row.
func matches(r Row, f Filter) bool {
	ts, _ := r["ts"].(time.Time)
	if !f.From.IsZero() && ts.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !ts.Before(f.To) {
		return false
	}
	for col, vals := range f.Equals {
		s := groupString(r[col])
		ok := false
		for _, v := range vals {
			if s == v {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func groupString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	}
	return fmt.Sprint(v)
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int64:
		return float64(x), true
	case int:
		return float64(x), true
	}
	return 0, false
}

// validateAgg checks an aggregate query against the schema.
func validateAgg(tables map[string]Table, q *AggQuery) (Table, error) {
	if q.Table == "" {
		q.Table = "records"
	}
	t, ok := tables[q.Table]
	if !ok {
		return t, fmt.Errorf("%w: %s", ErrUnknownTable, q.Table)
	}
	c, ok := t.column(q.Feature)
	if !ok || (c.Type != BigInt && c.Type != Double) {
		return t, fmt.Errorf("%w: %q is not a numeric column of %s", ErrBadColumn, q.Feature, q.Table)
	}
	for _, g := range q.GroupBy {
		if _, ok := t.column(g); !ok {
			return t, fmt.Errorf("%w: group column %q", ErrBadColumn, g)
		}
	}
	for col := range q.Filter.Equals {
		if _, ok := t.column(col); !ok {
			return t, fmt.Errorf("%w: filter column %q", ErrBadColumn, col)
		}
	}
	for _, p := range q.Quantiles {
		if p < 0 || p > 1 || math.IsNaN(p) {
			return t, fmt.Errorf("quantile %v outside [0,1]", p)
		}
	}
	for i := 1; i < len(q.Histogram); i++ {
		if !(q.Histogram[i] > q.Histogram[i-1]) {
			return t, errors.New("histogram bounds must be strictly ascending")
		}
	}
	if q.Bucket < 0 {
		return t, errors.New("negative bucket")
	}
	return t, nil
}

// aggregateRows computes an aggregate in Go. It defines the semantics the
// DuckDB backend reproduces in SQL.
func aggregateRows(q AggQuery, scan func(fn func(Row) error) error) ([]AggRow, error) {
	type acc struct {
		row  AggRow
		vals []float64
	}
	groups := map[string]*acc{}
	var order []string
	err := scan(func(r Row) error {
		x, ok := toFloat(r[q.Feature])
		if !ok {
			return nil
		}
		g := map[string]string{}
		key := ""
		for _, c := range q.GroupBy {
			s := groupString(r[c])
			g[c] = s
			key += strconv.Quote(s) + "\x00"
		}
		var bucket *time.Time
		if q.Bucket > 0 {
			ts := r["ts"].(time.Time)
			bus := q.Bucket.Microseconds()
			us := ts.UnixMicro()
			b := time.UnixMicro(floorDiv(us, bus) * bus).UTC()
			bucket = &b
			key += b.Format(time.RFC3339Nano)
		}
		a := groups[key]
		if a == nil {
			a = &acc{row: AggRow{Group: g, Bucket: bucket}}
			groups[key] = a
			order = append(order, key)
		}
		a.vals = append(a.vals, x)
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]AggRow, 0, len(groups))
	for _, k := range order {
		a := groups[k]
		r := a.row
		n := len(a.vals)
		r.Count = int64(n)
		sum := 0.0
		r.Min, r.Max = math.Inf(1), math.Inf(-1)
		for _, v := range a.vals {
			sum += v
			r.Min = math.Min(r.Min, v)
			r.Max = math.Max(r.Max, v)
		}
		r.Mean = sum / float64(n)
		if n > 1 {
			ss := 0.0
			for _, v := range a.vals {
				d := v - r.Mean
				ss += d * d
			}
			r.Variance = ss / float64(n-1)
		}
		if len(q.Quantiles) > 0 {
			s := append([]float64(nil), a.vals...)
			sort.Float64s(s)
			for _, p := range q.Quantiles {
				r.Quantiles = append(r.Quantiles, quantile(s, p))
			}
		}
		if len(q.Histogram) > 0 {
			r.Histogram = make([]int64, len(q.Histogram)+1)
			for _, v := range a.vals {
				i := sort.SearchFloat64s(q.Histogram, v) // first bound >= v
				r.Histogram[i]++
			}
		}
		out = append(out, r)
	}
	sortAgg(out)
	return out, nil
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// quantile is the linear interpolation of order statistics at (n-1)p, the
// definition of DuckDB quantile_cont.
func quantile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	h := float64(len(sorted)-1) * p
	lo := math.Floor(h)
	i := int(lo)
	if i+1 >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	return sorted[i] + (h-lo)*(sorted[i+1]-sorted[i])
}

func sortAgg(rows []AggRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ka, kb := groupKey(a.Group), groupKey(b.Group); ka != kb {
			return ka < kb
		}
		if a.Bucket != nil && b.Bucket != nil {
			return a.Bucket.Before(*b.Bucket)
		}
		return false
	})
}

func groupKey(g map[string]string) string {
	keys := make([]string, 0, len(g))
	for k := range g {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(g[k])
		sb.WriteByte(0)
	}
	return sb.String()
}

// appendRowJSON appends a normalized row as one JSON object and a newline,
// with its members in the column order of t. The normalized values
// (string, int64, float64, time.Time) are encoded directly; any other value
// is encoded with encoding/json. The object decodes to the values the
// encoding/json encoding of the row decodes to: one batch of span rows per
// call made the per-row encoder (a map per row, members sorted by
// reflection) most of the store's per-call cost (FR-11.4).
func appendRowJSON(b []byte, t Table, r Row) ([]byte, error) {
	b = append(b, '{')
	first := true
	for _, c := range t.Columns {
		v, ok := r[c.Name]
		if !ok {
			continue
		}
		if !first {
			b = append(b, ',')
		}
		first = false
		b = appendJSONString(b, c.Name)
		b = append(b, ':')
		switch x := v.(type) {
		case string:
			b = appendJSONString(b, x)
		case int64:
			b = strconv.AppendInt(b, x, 10)
		case float64:
			if math.IsInf(x, 0) || math.IsNaN(x) {
				return b, fmt.Errorf("%s.%s: unsupported value %v", t.Name, c.Name, x)
			}
			b = strconv.AppendFloat(b, x, 'g', -1, 64)
		case time.Time:
			b = append(b, '"')
			b = x.UTC().AppendFormat(b, tsLayout)
			b = append(b, '"')
		default:
			raw, err := json.Marshal(jsonValue(v))
			if err != nil {
				return b, err
			}
			b = append(b, raw...)
		}
	}
	return append(b, '}', '\n'), nil
}

// appendJSONString appends s as a JSON string: quotes, backslashes and
// control characters escaped, invalid UTF-8 replaced by U+FFFD, and U+2028
// and U+2029 escaped, as encoding/json does (without its HTML escaping,
// which does not change the decoded string).
func appendJSONString(b []byte, s string) []byte {
	const hex = "0123456789abcdef"
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, s[start:i]...)
			b = append(b, `\ufffd`...)
			i += size
			start = i
			continue
		}
		if r == '\u2028' || r == '\u2029' {
			b = append(b, s[start:i]...)
			b = append(b, '\\', 'u', '2', '0', '2', hex[r&0xf])
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}
