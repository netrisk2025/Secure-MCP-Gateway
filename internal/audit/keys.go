package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// LastTransition returns the next_key of the journal's last closed segment,
// or "" when that segment is not a key-transition record or no segment has
// closed. Startup uses it to finish or discard an interrupted evidence-key
// rotation.
func LastTransition(dir string) (string, error) {
	segs, err := listSegments(dir)
	if os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	for i := len(segs) - 1; i >= 0; i-- {
		ft, err := readFooter(filepath.Join(dir, segs[i].name))
		if err != nil {
			return "", err
		}
		if ft != nil {
			return ft.NextKey, nil
		}
	}
	return "", nil
}

// EmptyOpenSegment returns the name of the journal's trailing segment when
// it is not closed and holds no event yet (only its header), else "".
// Backups leave such a segment out: the archived journal then ends at a
// signed segment, and the restored Gateway opens the next one instead of
// sealing an empty segment as crash-recovered.
func EmptyOpenSegment(dir string) (string, error) {
	segs, err := listSegments(dir)
	if err != nil || len(segs) == 0 {
		return "", err
	}
	last := segs[len(segs)-1]
	path := filepath.Join(dir, last.name)
	ft, err := readFooter(path)
	if err != nil || ft != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if n := bytes.Count(b, []byte("\n")); n == 1 && bytes.HasSuffix(b, []byte("\n")) {
		var h header
		if json.Unmarshal(bytes.TrimSpace(b), &h) == nil && h.Type == lineHeader {
			return last.name, nil
		}
	}
	return "", nil
}

// LastSegment returns the name and SHA-256 of the journal's last segment
// file (open or closed), as printed by `smcpctl uninstall --purge`.
func LastSegment(dir string) (name, sum string, err error) {
	segs, err := listSegments(dir)
	if err != nil || len(segs) == 0 {
		return "", "", err
	}
	name = segs[len(segs)-1].name
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	return name, hex.EncodeToString(h.Sum(nil)), nil
}
