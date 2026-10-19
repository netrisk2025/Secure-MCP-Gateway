package obsstore

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// jsonlStore keeps each flushed batch as one JSON Lines file per day
// partition and evaluates queries in Go.
type jsonlStore struct{ *base }

func openJSONL(o Options) (Store, error) { return &jsonlStore{newBase(o)}, nil }

func (s *jsonlStore) Backend() string { return "jsonl" }

func (s *jsonlStore) Append(table string, rows []Row) error {
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
		if err := writeJSONL(filepath.Join(dir, s.nextName()+".jsonl"), t, rs, true); err != nil {
			return err
		}
	}
	s.countRows(table, len(norm))
	return nil
}

func (s *jsonlStore) Scan(table string, f Filter, fn func(Row) error) error {
	t, ok := s.tables[table]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownTable, table)
	}
	files, err := s.files(table, ".jsonl", f)
	if err != nil {
		return err
	}
	var rows []Row
	for _, path := range files {
		if err := readJSONL(path, t, func(r Row) {
			if matches(r, f) {
				rows = append(rows, r)
			}
		}); err != nil {
			return err
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i]["ts"].(time.Time).Before(rows[j]["ts"].(time.Time)) })
	for i, r := range rows {
		if f.Limit > 0 && i >= f.Limit {
			break
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

// readJSONL decodes rows and restores the column types. Keys that are not
// columns of the current schema are kept as decoded.
func readJSONL(path string, t Table, fn func(Row)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	for sc.Scan() {
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.UseNumber()
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		r := Row{}
		for k, v := range obj {
			c, ok := t.column(k)
			if !ok {
				r[k] = v
				continue
			}
			nv, err := convert(c, v)
			if err != nil {
				return fmt.Errorf("%s: %s: %w", path, k, err)
			}
			r[k] = nv
		}
		fn(r)
	}
	return sc.Err()
}

func (s *jsonlStore) Aggregate(q AggQuery) ([]AggRow, error) {
	if _, err := validateAgg(s.tables, &q); err != nil {
		return nil, err
	}
	return aggregateRows(q, func(fn func(Row) error) error { return s.Scan(q.Table, q.Filter, fn) })
}

func (s *jsonlStore) Retain(now time.Time, keep time.Duration) ([]string, error) {
	return s.retain(now, keep)
}

func (s *jsonlStore) Stats() (Stats, error) { return s.stats("jsonl") }

func (s *jsonlStore) Close() error { return nil }
