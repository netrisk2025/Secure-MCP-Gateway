package filters

import (
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Match is one rule hit. Start and End are byte offsets into the scanned
// text; for a normalized rule set they index the normalized text and are
// used only for counting.
type Match struct {
	Rule       *Rule
	Start, End int
}

// Scan applies every rule of the set to text.
func (rs *RuleSet) Scan(text string) []Match {
	if text == "" {
		return nil
	}
	subject := text
	if rs.Normalize {
		subject = normalizeText(text)
	}
	var out []Match
	pf := &prefilterText{s: subject}
	for _, r := range rs.Rules {
		if r.re != nil && !pf.mayMatch(r.lits) {
			continue // none of the literals the rule needs is in the text
		}
		out = append(out, r.scan(subject)...)
	}
	return out
}

func (r *Rule) scan(s string) []Match {
	switch r.Kind {
	case "codepoints":
		return r.scanCodepoints(s)
	case "entropy":
		var out []Match
		for _, loc := range r.findAll(s) {
			tok := s[loc[0]:loc[1]]
			if len(tok) >= r.MinLength && classes(tok) >= r.MinClasses && entropy(tok) >= r.MinEntropy {
				out = append(out, Match{Rule: r, Start: loc[0], End: loc[1]})
			}
		}
		return out
	case "luhn":
		var out []Match
		for _, loc := range r.findAll(s) {
			if luhn(s[loc[0]:loc[1]]) {
				out = append(out, Match{Rule: r, Start: loc[0], End: loc[1]})
			}
		}
		return out
	default:
		var out []Match
		for _, loc := range r.findAll(s) {
			out = append(out, Match{Rule: r, Start: loc[0], End: loc[1]})
		}
		return out
	}
}

// scanCodepoints finds maximal runs of the rule's code points and reports
// each run whose context is not permitted.
func (r *Rule) scanCodepoints(s string) []Match {
	var out []Match
	prev := rune(-1)
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf && r.asciiFree {
			prev = rune(b)
			i++
			continue
		}
		c, w := utf8.DecodeRuneInString(s[i:])
		if !unicode.Is(r.ranges, c) {
			prev = c
			i += w
			continue
		}
		start := i
		for i < len(s) {
			c2, w2 := utf8.DecodeRuneInString(s[i:])
			if !unicode.Is(r.ranges, c2) {
				break
			}
			i += w2
		}
		next := rune(-1)
		if i < len(s) {
			next, _ = utf8.DecodeRuneInString(s[i:])
		}
		if !r.permitted(start, prev, next) {
			out = append(out, Match{Rule: r, Start: start, End: i})
		}
		prev = -1 // the run itself precedes what follows
		if i > 0 {
			prev, _ = utf8.DecodeLastRuneInString(s[:i])
		}
	}
	return out
}

func (r *Rule) permitted(start int, prev, next rune) bool {
	if r.PermitAtStart && start == 0 {
		return true
	}
	if r.after != nil && prev >= 0 && unicode.Is(r.after, prev) {
		return true
	}
	if r.PermitEmoji && prev >= 0 && next >= 0 && pictographic(prev) && pictographic(next) {
		return true
	}
	if len(r.scripts) > 0 && prev >= 0 && next >= 0 && inScripts(prev, r.scripts) && inScripts(next, r.scripts) {
		return true
	}
	return false
}

func inScripts(c rune, scripts []*unicode.RangeTable) bool {
	for _, t := range scripts {
		if unicode.Is(t, c) {
			return true
		}
	}
	return false
}

// pictographic approximates Extended_Pictographic plus the emoji modifiers
// and presentation selector that appear inside ZWJ sequences.
func pictographic(c rune) bool {
	switch {
	case c >= 0x1F000 && c <= 0x1FAFF, c >= 0x2600 && c <= 0x27BF, c >= 0x2300 && c <= 0x23FF,
		c >= 0x2B00 && c <= 0x2BFF, c == 0xFE0F, c == 0x20E3, c == 0x2640, c == 0x2642, c == 0x2695:
		return true
	}
	return false
}

// normalizeText prepares text for phrase rules: NFKC (folds full-width and
// compatibility forms), removal of format characters (zero-width, bidi and
// tag characters that split words), lower case and collapsed whitespace.
func normalizeText(s string) string {
	s = norm.NFKC.String(s)
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); {
		// ASCII: no format characters; the spaces are \t \n \v \f \r and
		// the space itself.
		if c := s[i]; c < utf8.RuneSelf {
			i++
			switch {
			case c == ' ' || (c >= '\t' && c <= '\r'):
				if !space {
					b.WriteByte(' ')
				}
				space = true
			case c >= 'A' && c <= 'Z':
				space = false
				b.WriteByte(c + 'a' - 'A')
			default:
				space = false
				b.WriteByte(c)
			}
			continue
		}
		c, w := utf8.DecodeRuneInString(s[i:])
		i += w
		if unicode.Is(unicode.Cf, c) {
			continue
		}
		if unicode.IsSpace(c) {
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(unicode.ToLower(c))
	}
	return b.String()
}

func classes(s string) int {
	var up, lo, dig, oth bool
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= '0' && c <= '9':
			dig = true
		default:
			oth = true
		}
	}
	n := 0
	for _, b := range []bool{up, lo, dig, oth} {
		if b {
			n++
		}
	}
	return n
}

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func luhn(s string) bool {
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if (len(digits)-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
