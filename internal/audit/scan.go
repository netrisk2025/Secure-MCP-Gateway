package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
)

// Segment names one journal segment file in order.
type Segment struct {
	Seq  int
	Name string
}

// Segments lists the journal segments of dir in sequence order.
func Segments(dir string) ([]Segment, error) {
	segs, err := listSegments(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Segment, len(segs))
	for i, s := range segs {
		out[i] = Segment{Seq: s.seq, Name: s.name}
	}
	return out, nil
}

// ScanSegment streams the events of one segment to fn in order and reports
// whether the segment is sealed (ends with a footer). A trailing partial
// line of an open segment is skipped. It does not verify; mirrors that are
// rebuilt from the journal use it so that memory stays bounded by one line.
// An error returned by fn stops the scan and is returned.
func ScanSegment(dir string, s Segment, fn func(Event) error) (sealed bool, err error) {
	f, err := os.Open(filepath.Join(dir, s.Name))
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<26)
	for sc.Scan() {
		var line struct {
			Type string `json:"type"`
			Event
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		switch line.Type {
		case lineEvent:
			if err := fn(line.Event); err != nil {
				return false, err
			}
		case lineFooter:
			sealed = true
		}
	}
	return sealed, sc.Err()
}
