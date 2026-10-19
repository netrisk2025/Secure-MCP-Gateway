package secrets

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Window is the fingerprint window length of FR-6.10: every 12-byte
// substring of each encoded form is fingerprinted.
const Window = 12

// MinValueBytes is the shortest secret value the vault accepts. Shorter
// values would make fingerprints match ordinary text.
const MinValueBytes = 8

type fpInfo struct {
	ref     string
	version int
	form    string
}

// Fingerprints is the keyed leak-detection set (FR-6.10). Each delivered
// secret version contributes HMAC-SHA-256 digests, under a key generated
// at random when the set is created and never stored, of:
//
//   - every 12-byte window of its raw value, its hex (lower and upper
//     case), URL query- and path-escaped forms;
//   - every 12-byte window of its standard and URL-safe Base64 encodings at
//     each of the three byte alignments, so a value Base64-encoded inside a
//     larger string is still found;
//   - the full value of every form shorter than 12 bytes.
//
// The set holds no plaintext. It implements pipeline.SecretFingerprints.
type Fingerprints struct {
	key []byte

	mu    sync.RWMutex
	set   map[[32]byte]fpInfo
	short map[int]int // form length (< Window) -> registered count
	done  map[string]bool
	sinks []func(ref string, version int, value []byte)
}

// OnRegister adds a function that receives each secret version when it is
// first registered, so another leak-detection set (the E-09/E-11 filters'
// registered fingerprints) learns it too. fn must not keep value.
func (f *Fingerprints) OnRegister(fn func(ref string, version int, value []byte)) {
	f.mu.Lock()
	f.sinks = append(f.sinks, fn)
	f.mu.Unlock()
}

var _ pipeline.SecretFingerprints = (*Fingerprints)(nil)

// NewFingerprints returns an empty set with a fresh random key.
func NewFingerprints() *Fingerprints {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("secrets: no randomness: " + err.Error())
	}
	return &Fingerprints{key: key, set: map[[32]byte]fpInfo{}, short: map[int]int{}, done: map[string]bool{}}
}

type form struct {
	name   string
	full   []byte // the complete encoded form
	region []byte // the part made only of the value's bytes (windows)
}

// forms returns every encoded form of value that is fingerprinted.
func forms(value []byte) []form {
	out := []form{{name: "raw", full: value, region: value}}
	hx := []byte(hex.EncodeToString(value))
	out = append(out, form{name: "hex", full: hx, region: hx})
	up := []byte(strings.ToUpper(string(hx)))
	out = append(out, form{name: "HEX", full: up, region: up})
	if q := url.QueryEscape(string(value)); q != string(value) {
		out = append(out, form{name: "query", full: []byte(q), region: []byte(q)})
	}
	if p := url.PathEscape(string(value)); p != string(value) {
		out = append(out, form{name: "path", full: []byte(p), region: []byte(p)})
	}
	for _, enc := range []struct {
		name string
		e    *base64.Encoding
	}{{"base64", base64.StdEncoding}, {"base64url", base64.URLEncoding}} {
		for k := 0; k < 3; k++ {
			buf := make([]byte, k+len(value))
			copy(buf[k:], value)
			s := []byte(enc.e.EncodeToString(buf))
			wipe(buf)
			// Character i encodes bits [6i, 6i+6) of the input. Only the
			// characters wholly inside the value's bits are independent of
			// what surrounds the value in a larger encoded string.
			first := (8*k + 5) / 6
			last := (8*(k+len(value)))/6 - 1
			f := form{name: enc.name}
			if k == 0 {
				f.full = s
			}
			if last >= first {
				f.region = s[first : last+1]
			}
			out = append(out, f)
		}
	}
	return out
}

func (f *Fingerprints) mac(h hash.Hash, b []byte) [32]byte {
	h.Reset()
	h.Write(b)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// Register adds the fingerprints of one secret version. Registering the
// same reference and version again is a no-op. The caller keeps ownership
// of value and may wipe it afterwards.
func (f *Fingerprints) Register(ref string, version int, value []byte) {
	id := ref + "@" + strconv.Itoa(version)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done[id] {
		return
	}
	f.done[id] = true
	for _, fn := range f.sinks {
		fn(ref, version, value)
	}
	h := hmac.New(sha256.New, f.key)
	for _, fm := range forms(value) {
		info := fpInfo{ref: ref, version: version, form: fm.name}
		if len(fm.full) >= MinValueBytes && len(fm.full) < Window {
			f.set[f.mac(h, fm.full)] = info
			f.short[len(fm.full)]++
		}
		for i := 0; i+Window <= len(fm.region); i++ {
			f.set[f.mac(h, fm.region[i:i+Window])] = info
		}
		if fm.name != "raw" {
			wipe(fm.full)
			wipe(fm.region)
		}
	}
}

// Len implements pipeline.SecretFingerprints.
func (f *Fingerprints) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.set)
}

// Scan implements pipeline.SecretFingerprints.
func (f *Fingerprints) Scan(data []byte) []pipeline.SecretMatch {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.set) == 0 || len(data) == 0 {
		return nil
	}
	lengths := []int{Window}
	for l := range f.short {
		lengths = append(lengths, l)
	}
	h := hmac.New(sha256.New, f.key)
	var raw []pipeline.SecretMatch
	for _, l := range lengths {
		for i := 0; i+l <= len(data); i++ {
			if info, ok := f.set[f.mac(h, data[i:i+l])]; ok {
				raw = append(raw, pipeline.SecretMatch{SecretRef: info.ref, Version: info.version, Form: info.form, Start: i, End: i + l})
			}
		}
	}
	return merge(raw)
}

// merge joins overlapping or adjacent spans of the same secret version.
func merge(ms []pipeline.SecretMatch) []pipeline.SecretMatch {
	if len(ms) == 0 {
		return nil
	}
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].SecretRef != ms[j].SecretRef {
			return ms[i].SecretRef < ms[j].SecretRef
		}
		if ms[i].Version != ms[j].Version {
			return ms[i].Version < ms[j].Version
		}
		return ms[i].Start < ms[j].Start
	})
	out := []pipeline.SecretMatch{ms[0]}
	for _, m := range ms[1:] {
		last := &out[len(out)-1]
		if m.SecretRef == last.SecretRef && m.Version == last.Version && m.Start <= last.End {
			if m.End > last.End {
				last.End = m.End
			}
			continue
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// Redact implements pipeline.SecretFingerprints.
func (f *Fingerprints) Redact(data []byte) ([]byte, []pipeline.SecretMatch) {
	ms := f.Scan(data)
	if len(ms) == 0 {
		return data, nil
	}
	var out []byte
	pos := 0
	for _, m := range ms { // sorted by Start
		if m.End <= pos {
			continue
		}
		start := max(m.Start, pos)
		out = append(out, data[pos:start]...)
		out = append(out, "[REDACTED:"+m.SecretRef+"]"...)
		pos = m.End
	}
	out = append(out, data[pos:]...)
	return out, ms
}

// RedactString is Redact for strings.
func (f *Fingerprints) RedactString(s string) string {
	b, ms := f.Redact([]byte(s))
	if len(ms) == 0 {
		return s
	}
	return string(b)
}

// wipe overwrites b with zeros (SR-2.13-2).
func wipe(b []byte) {
	clear(b)
}
