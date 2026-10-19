package filters

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash/maphash"
	"strings"
	"sync"
	"unicode"
)

// FingerprintWindow is the FR-6.10 substring length.
const FingerprintWindow = 12

// FingerprintSet holds non-reversible detectors for registered secret
// values (FR-6.10, ARCH §8.5): a keyed HMAC-SHA-256 of each value's full
// form and of every 12-character substring of its raw, Base64, hex and
// URL-encoded forms. Plaintext is never retained. A process-local seeded
// 64-bit hash of each window is kept as a prefilter so that scanning a
// large result costs one cheap hash per byte; a prefilter hit is confirmed
// with the HMAC. The keys are random per process and never leave memory.
//
// The Secret Broker (E-20) registers values here when it delivers a
// secret; until it exists, nothing is registered and the set matches
// nothing.
type FingerprintSet struct {
	mu      sync.RWMutex
	key     []byte
	seed    maphash.Seed
	pre     map[uint64]struct{}
	windows map[[32]byte]string // HMAC of a window -> secret reference
	full    map[[32]byte]string // HMAC of a whole short value -> reference
}

// NewFingerprintSet returns an empty set with fresh keys.
func NewFingerprintSet() *FingerprintSet {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return &FingerprintSet{key: key, seed: maphash.MakeSeed(), pre: map[uint64]struct{}{},
		windows: map[[32]byte]string{}, full: map[[32]byte]string{}}
}

func (f *FingerprintSet) mac(s string) [32]byte {
	m := hmac.New(sha256.New, f.key)
	m.Write([]byte(s))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func (f *FingerprintSet) macBytes(b []byte) [32]byte {
	m := hmac.New(sha256.New, f.key)
	m.Write(b)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// encodedFormsBytes are the forms of encodedForms built as byte slices the
// caller can overwrite. The first is v itself.
func encodedFormsBytes(v []byte) [][]byte {
	out := [][]byte{v}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b := make([]byte, enc.EncodedLen(len(v)))
		enc.Encode(b, v)
		out = append(out, b)
	}
	lower := make([]byte, hex.EncodedLen(len(v)))
	hex.Encode(lower, v)
	upper := make([]byte, len(lower))
	for i, c := range lower {
		if c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		upper[i] = c
	}
	return append(out, lower, upper, escapeBytes(v, true), escapeBytes(v, false))
}

// escapeBytes is url.QueryEscape (query) or url.PathEscape on bytes.
func escapeBytes(v []byte, query bool) []byte {
	const hexdig = "0123456789ABCDEF"
	out := make([]byte, 0, 3*len(v))
	for _, c := range v {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			out = append(out, c)
		case query && c == ' ':
			out = append(out, '+')
		case !query && (c == '$' || c == '&' || c == '+' || c == ':' || c == '=' || c == '@'):
			out = append(out, c)
		default:
			out = append(out, '%', hexdig[c>>4], hexdig[c&15])
		}
	}
	return out
}

// Register adds the fingerprints of value under ref (a secret reference,
// never the value). Values shorter than the window match only as a whole
// token.
func (f *FingerprintSet) Register(ref, value string) {
	b := []byte(value)
	f.RegisterBytes(ref, b)
	clear(b)
}

// RegisterBytes is Register for a value held in a byte slice (the Secret
// Broker's deliveries, SR-2.13-2): every encoded form is built in a buffer
// that is overwritten once its fingerprints are computed, so no immutable
// copy of the value or of its encodings is left behind. value itself is
// neither kept nor changed.
func (f *FingerprintSet) RegisterBytes(ref string, value []byte) {
	if len(value) == 0 {
		return
	}
	f.registerForms(ref, encodedFormsBytes(value))
}

// registerForms fingerprints forms (forms[0] is the caller's value) and
// overwrites every other form.
func (f *FingerprintSet) registerForms(ref string, forms [][]byte) {
	defer func() {
		for _, b := range forms[1:] {
			clear(b)
		}
	}()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, form := range forms {
		f.full[f.macBytes(form)] = ref
		if len(form) < FingerprintWindow {
			continue
		}
		for i := 0; i+FingerprintWindow <= len(form); i++ {
			w := form[i : i+FingerprintWindow]
			f.pre[maphash.Bytes(f.seed, w)] = struct{}{}
			f.windows[f.macBytes(w)] = ref
		}
	}
}

// Len reports the number of window fingerprints held.
func (f *FingerprintSet) Len() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.windows) + len(f.full)
}

// Match reports whether s contains a registered secret fragment, and which
// reference matched.
func (f *FingerprintSet) Match(s string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.full) == 0 {
		return "", false
	}
	for i := 0; i+FingerprintWindow <= len(s); i++ {
		w := s[i : i+FingerprintWindow]
		if _, hit := f.pre[maphash.String(f.seed, w)]; !hit {
			continue
		}
		if ref, ok := f.windows[f.mac(w)]; ok {
			return ref, true
		}
	}
	for _, tok := range strings.FieldsFunc(s, func(c rune) bool {
		return !(unicode.IsLetter(c) || unicode.IsDigit(c) || strings.ContainsRune("-_.+/=%~!@#$^&*", c))
	}) {
		if ref, ok := f.full[f.mac(tok)]; ok {
			return ref, true
		}
	}
	return "", false
}
