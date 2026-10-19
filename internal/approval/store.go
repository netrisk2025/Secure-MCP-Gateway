package approval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// StoreDir is the directory under the state directory that holds approval
// records, one JSON file per approval, mode 0600.
const StoreDir = "approvals"

var idPattern = regexp.MustCompile(`^[0-9a-f-]{36}$`)

// store persists records. Writes go to a temporary file that is synced and
// renamed over the record, so a crash leaves either the old or the new
// record.
type store struct{ dir string }

func openStore(stateDir string) (*store, error) {
	dir := filepath.Join(stateDir, StoreDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &store{dir: dir}, nil
}

func (s *store) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *store) put(r *Record) error {
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("approval id %q is malformed", r.ID)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path(r.ID)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (s *store) remove(id string) error {
	if !idPattern.MatchString(id) {
		return nil
	}
	err := os.Remove(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// load reads every record. Unreadable files are reported and skipped.
func (s *store) load() ([]*Record, []error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, []error{err}
	}
	var out []*Record
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil || r.ID+".json" != name {
			errs = append(errs, fmt.Errorf("%s: unreadable approval record", name))
			continue
		}
		out = append(out, &r)
	}
	return out, errs
}
