package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanSegmentStreamsEventsAndReportsSealed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	j, err := Open(dir, key, Options{MaxEvents: 3, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err := j.Record(Event{Class: "test", Origin: "E-21"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Sync(); err != nil {
		t.Fatal(err)
	}
	segs, err := Segments(dir)
	if err != nil || len(segs) != 3 {
		t.Fatalf("%v %v", segs, err)
	}
	total := 0
	for i, s := range segs {
		n := 0
		sealed, err := ScanSegment(dir, s, func(Event) error { n++; return nil })
		if err != nil {
			t.Fatal(err)
		}
		if want := i < 2; sealed != want {
			t.Fatalf("segment %d sealed=%v", s.Seq, sealed)
		}
		total += n
	}
	if total != 7 {
		t.Fatalf("%d events", total)
	}
	// A partial trailing line of the open segment is skipped.
	f, err := os.OpenFile(filepath.Join(dir, segs[2].Name), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"type":"event","event_id":"tru`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	n := 0
	if _, err := ScanSegment(dir, segs[2], func(Event) error { n++; return nil }); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	_ = j.Close()
}
