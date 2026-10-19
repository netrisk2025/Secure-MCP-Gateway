package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Feature extraction for the request-shape (P-024 to P-044) and
// response-shape (P-120 to P-127) parameters. Each function follows the
// derivation column of docs/parameters.json; deviations are listed in
// docs/observation.md.

// Entropy is the Shannon entropy in bits per character over the UTF-8 code
// points of s (P-028, P-123). The empty string has entropy 0.
func Entropy(s string) float64 {
	h, _ := entropyCount(s)
	return h
}

// entropyCount returns Entropy(s) and the number of code points in s.
// ASCII code points are counted in an array; a map holds the others only
// when there are any (the per-call cost of a large text result is the
// FR-11.4 budget's).
func entropyCount(s string) (float64, int) { return entropyOfParts([]string{s}) }

// entropyOfParts is entropyCount of the concatenation of valid UTF-8
// parts, without concatenating them.
func entropyOfParts(parts []string) (float64, int) {
	h, n, _ := textStats(parts)
	return h, n
}

// textStats is entropyOfParts and, from the same pass, the sum of the
// parts' lengths as encoding/json writes them inside string literals
// (jsonStringLen). The probe of a large text result reads it once instead
// of twice: the encoded length was a second pass over the text, about half
// of the observe-response probe's time on the call path (FR-11.4).
func textStats(parts []string) (float64, int, int) {
	// Four tables, summed below, so that runs of equal bytes do not
	// serialize on one counter.
	var tab [4][utf8.RuneSelf]int
	var other map[rune]int
	n := 0
	jsonLen := 0 // of the non-ASCII code points here; of the ASCII bytes from tab below
	for _, s := range parts {
		i := 0
		for ; i+4 <= len(s); i += 4 {
			b0, b1, b2, b3 := s[i], s[i+1], s[i+2], s[i+3]
			if (b0|b1|b2|b3)&0x80 != 0 {
				break
			}
			tab[0][b0]++
			tab[1][b1]++
			tab[2][b2]++
			tab[3][b3]++
			n += 4
		}
		for i < len(s) {
			if b := s[i]; b < utf8.RuneSelf {
				tab[0][b]++
				i++
			} else {
				r, size := utf8.DecodeRuneInString(s[i:])
				if other == nil {
					other = map[rune]int{}
				}
				other[r]++
				jsonLen += jsonRuneLen(r, size)
				i += size
			}
			n++
		}
	}
	if n == 0 {
		return 0, 0, 0
	}
	h := 0.0
	add := func(c int) {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	for b := range tab[0] {
		if c := tab[0][b] + tab[1][b] + tab[2][b] + tab[3][b]; c > 0 {
			add(c)
			jsonLen += c * int(jsonASCIILen[b])
		}
	}
	for _, c := range other {
		add(c)
	}
	return h, n, jsonLen
}

// unicodeControl counts control and format characters other than tab,
// newline and carriage return (P-044): C0/C1 controls, bidirectional
// overrides, zero-width characters and other Cf code points.
func unicodeControl(s string) int {
	n := 0
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			n++
		}
	}
	return n
}

// looksLikePath reports a string leaf that is an absolute, home-relative
// or dot-relative filesystem path.
func looksLikePath(s string) bool {
	if len(s) > 4096 || strings.ContainsAny(s, "\n\x00") {
		return false
	}
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		(len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') && unicode.IsLetter(rune(s[0])))
}

// looksLikeURL reports a string leaf that parses as an absolute URL with a
// scheme and a host.
func looksLikeURL(s string) bool {
	if len(s) > 8192 || !strings.Contains(s, "://") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

type walkStats struct {
	maxDepth int
	strLens  []int
	text     strings.Builder
	paths    int
	urls     int
	controls int
	fields   int
}

func (w *walkStats) walk(v any, depth int) {
	if depth > w.maxDepth {
		w.maxDepth = depth
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.fields++
			w.controls += unicodeControl(k)
			w.walk(x[k], depth+1)
		}
	case []any:
		for _, e := range x {
			w.walk(e, depth+1)
		}
	case string:
		w.strLens = append(w.strLens, utf8.RuneCountInString(x))
		if w.text.Len() < 1<<20 {
			w.text.WriteString(x)
		}
		if looksLikePath(x) {
			w.paths++
		}
		if looksLikeURL(x) {
			w.urls++
		}
		w.controls += unicodeControl(x)
	}
}

// ArgumentFeatures computes the request-shape parameters from the tool-call
// arguments as received (a JSON object or null).
//
//   - request_bytes (P-024): length of the arguments JSON.
//   - argument_count (P-025): number of top-level arguments.
//   - argument_max_depth (P-026): nesting depth; the arguments object is
//     depth 1, a scalar inside it depth 1, an object inside it depth 2.
//   - argument_string_lengths (P-027): code-point length of each string
//     leaf, in document order of a sorted-key walk.
//   - argument_entropy (P-028): entropy of the concatenated string leaves.
//   - path_argument_count, url_argument_count (P-029, P-030): string
//     leaves that look like paths or absolute URLs.
//   - argument_value_hashes (P-040): sha256 of each top-level argument's
//     canonical JSON, by argument name (S2).
//   - unicode_control_count (P-044).
//
// It also returns the digest of the whole canonical argument object, used
// for repeated_identical_calls (P-066).
func ArgumentFeatures(args json.RawMessage) (map[string]any, string) {
	out := map[string]any{"request_bytes": int64(len(args))}
	var obj map[string]any
	if len(args) > 0 && string(args) != "null" {
		if err := json.Unmarshal(args, &obj); err != nil {
			out["argument_count"] = int64(0)
			return out, ""
		}
	}
	canon, _ := json.Marshal(obj) // encoding/json sorts map keys: canonical enough for a digest
	sum := sha256.Sum256(canon)
	digest := hex.EncodeToString(sum[:])
	w := &walkStats{}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	hashes := map[string]string{}
	for _, k := range keys {
		w.controls += unicodeControl(k)
		w.walk(obj[k], 1)
		raw, _ := json.Marshal(obj[k])
		h := sha256.Sum256(raw)
		hashes[k] = hex.EncodeToString(h[:])
	}
	if len(obj) > 0 && w.maxDepth < 1 {
		w.maxDepth = 1
	}
	lens := make([]int64, len(w.strLens))
	for i, l := range w.strLens {
		lens[i] = int64(l)
	}
	out["argument_count"] = int64(len(obj))
	out["argument_max_depth"] = int64(w.maxDepth)
	out["argument_string_lengths"] = lens
	out["argument_entropy"] = Entropy(w.text.String())
	out["path_argument_count"] = int64(w.paths)
	out["url_argument_count"] = int64(w.urls)
	out["argument_value_hashes"] = hashes
	out["unicode_control_count"] = int64(w.controls)
	return out, digest
}

// ResponseFeatures computes the response-shape parameters from a tool
// result.
//
//   - response_bytes (P-120): length of the result's JSON encoding.
//   - content_parts_by_type (P-121): count of content parts per type.
//   - output_schema_conformance (P-122): "conforms", "violates" or
//     "no_schema" (validator supplied by the caller).
//   - response_entropy (P-123): entropy of the text parts.
//   - response_token_estimate (P-124): text characters divided by 4.
//   - is_error (P-125): {"is_error": bool}.
//   - structured_field_count (P-126): recursive field count of
//     structuredContent.
//   - embedded_url_count (P-127): resource links, embedded resources and
//     absolute URLs in text.
func ResponseFeatures(res *mcp.CallToolResult, validate func(structured any) string, hasSchema bool) map[string]any {
	out, finish := ResponseFeaturesDeferred(res, validate, hasSchema)
	finish()
	return out
}

// ResponseFeaturesDeferred is ResponseFeatures in two parts. It returns
// the parameters that need only the result's shape, and finish, which
// adds those that read the text parts (response_bytes, response_entropy,
// response_token_estimate and embedded_url_count) to the same map. finish
// reads nothing of res but the text parts' strings, which never change, so
// it may run later on another goroutine once the map has been handed over:
// with asynchronous scoring the observe-response probe leaves it to the
// Observation Collector, and a large text result is no longer read on the
// call path (FR-11.4).
func ResponseFeaturesDeferred(res *mcp.CallToolResult, validate func(structured any) string, hasSchema bool) (out map[string]any, finish func()) {
	out = map[string]any{}
	if res == nil {
		return out, func() {}
	}
	parts := map[string]int64{}
	var texts []string // the text parts, not copied
	urls := 0
	for _, c := range res.Content {
		switch x := c.(type) {
		case *mcp.TextContent:
			parts["text"]++
			texts = append(texts, x.Text)
		case *mcp.ImageContent:
			parts["image"]++
		case *mcp.AudioContent:
			parts["audio"]++
		case *mcp.ResourceLink:
			parts["resource_link"]++
			urls++
		case *mcp.EmbeddedResource:
			parts["resource"]++
			urls++
		default:
			parts["other"]++
		}
	}
	out["content_parts_by_type"] = parts
	skeleton, skelErr := encodedSkeleton(res)
	out["is_error"] = map[string]any{"is_error": res.IsError}
	if res.StructuredContent != nil {
		var v any
		if b, err := json.Marshal(res.StructuredContent); err == nil && json.Unmarshal(b, &v) == nil {
			w := &walkStats{}
			w.walk(v, 0)
			out["structured_field_count"] = int64(w.fields)
		}
	} else {
		out["structured_field_count"] = int64(0)
	}
	switch {
	case !hasSchema:
		out["output_schema_conformance"] = "no_schema"
	case res.StructuredContent == nil:
		out["output_schema_conformance"] = "violates"
	case validate != nil && validate(res.StructuredContent) != "":
		out["output_schema_conformance"] = "violates"
	default:
		out["output_schema_conformance"] = "conforms"
	}
	finish = func() {
		var counted []string // the text parts up to 4 MiB
		textLen, restJSON := 0, 0
		textURLs := 0
		for _, s := range texts {
			if textLen < 4<<20 {
				counted = append(counted, s)
				textLen += len(s)
			} else {
				restJSON += jsonStringLen(s)
			}
			if strings.Contains(s, "://") { // looksLikeURL needs a scheme separator
				for _, f := range strings.Fields(s) {
					if looksLikeURL(strings.Trim(f, `"'()<>[],.`)) {
						textURLs++
					}
				}
			}
		}
		h, runes, textJSON := textStats(counted)
		if skelErr == nil {
			out["response_bytes"] = skeleton + int64(textJSON+restJSON)
		}
		out["response_entropy"] = h
		out["response_token_estimate"] = int64(runes / 4)
		out["embedded_url_count"] = int64(urls + textURLs)
	}
	return out, finish
}

// encodedSkeleton is the length of res's JSON encoding (P-120) without its
// text parts' encoded strings: each non-empty text part is encoded with a
// one-byte placeholder, which is subtracted. Adding the text parts' encoded
// lengths (jsonStringLen, or textStats) gives the length of the encoding,
// without encoding, and compacting, a large text result again.
func encodedSkeleton(res *mcp.CallToolResult) (int64, error) {
	cp := *res
	cp.Content = make([]mcp.Content, len(res.Content))
	placeholders := 0
	for i, c := range res.Content {
		if x, ok := c.(*mcp.TextContent); ok && len(x.Text) > 0 {
			t := *x
			t.Text = "x"
			cp.Content[i] = &t
			placeholders++
			continue
		}
		cp.Content[i] = c
	}
	raw, err := json.Marshal(&cp)
	if err != nil {
		return 0, err
	}
	return int64(len(raw) - placeholders), nil
}

// jsonStringLen is the length of s as encoding/json writes it inside a
// string literal, quotes excluded: HTML-escaped, with control characters,
// U+2028, U+2029 and invalid UTF-8 (as U+FFFD) escaped as encoding/json
// does.
func jsonStringLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			n += int(jsonASCIILen[b])
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		n += jsonRuneLen(r, size)
		i += size
	}
	return n
}

// jsonRuneLen is the encoded length in a JSON string of a non-ASCII code
// point read as size bytes: invalid UTF-8 is written as \ufffd, and U+2028
// and U+2029 are escaped.
func jsonRuneLen(r rune, size int) int {
	switch {
	case r == utf8.RuneError && size == 1:
		return 6 // \ufffd
	case r == '\u2028' || r == '\u2029':
		return 6
	}
	return size
}

// jsonASCIILen is the encoded length of each ASCII byte in a JSON string.
var jsonASCIILen = func() (t [utf8.RuneSelf]uint8) {
	for b := range t {
		switch {
		case b == '"' || b == '\\' || b == '\n' || b == '\r' || b == '\t' || b == '\b' || b == '\f':
			t[b] = 2
		case b < 0x20 || b == '<' || b == '>' || b == '&':
			t[b] = 6 // \u00XX
		default:
			t[b] = 1
		}
	}
	return t
}()
