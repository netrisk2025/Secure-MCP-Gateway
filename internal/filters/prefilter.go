package filters

import (
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// A required-literal prefilter for regex, luhn and entropy rules. Go's
// regexp scans a large text with its NFA at a few tens of nanoseconds per
// byte and pattern, so a 64 KiB tool result cost each rule about 1.5 ms
// and a response inspection about 35 ms of CPU (FR-11.5). Most rules
// cannot match without one of a few literals (a keyword, a token prefix, a
// marker); when none occurs in the text, which strings.Contains finds in
// microseconds, the rule cannot match and its regexp does not run.
//
// The literal set is derived from the parsed pattern conservatively: a
// node that could match without one of the literals yields no set, and a
// rule without a set always runs its regexp.

// literal is one required literal. fold marks a case-insensitive literal;
// fold literals are ASCII (lower case) and are looked up in the ASCII
// lower-cased text, which is exact only for an ASCII text (Unicode case
// folding maps some non-ASCII letters to ASCII ones), so a non-ASCII text
// always runs the regexp of a rule with a fold literal.
type literal struct {
	s    string
	fold bool
}

// requiredLiterals returns literals of which every match of pattern
// contains at least one, or nil when no such set is known.
func requiredLiterals(pattern string) []literal {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	return required(re.Simplify())
}

func required(re *syntax.Regexp) []literal {
	switch re.Op {
	case syntax.OpLiteral:
		s := string(re.Rune)
		if s == "" {
			return nil
		}
		if re.Flags&syntax.FoldCase != 0 {
			for i := 0; i < len(s); i++ {
				if s[i] >= utf8.RuneSelf {
					return nil // a non-ASCII fold literal: no exact ASCII lookup
				}
			}
			return []literal{{strings.ToLower(s), true}}
		}
		return []literal{{s, false}}
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil
	case syntax.OpConcat:
		// Every part must match, so any part's set will do; take the one
		// whose shortest literal is longest (the most selective).
		var best []literal
		bestLen := 0
		for _, sub := range re.Sub {
			lits := required(sub)
			if lits == nil {
				continue
			}
			if n := shortest(lits); n > bestLen {
				best, bestLen = lits, n
			}
		}
		return best
	case syntax.OpAlternate:
		var out []literal
		for _, sub := range re.Sub {
			lits := required(sub)
			if lits == nil {
				return nil // this alternative needs none of them
			}
			out = append(out, lits...)
		}
		return out
	}
	// Character classes, any-character, empty-width assertions, empty
	// matches, star and quest: nothing is required.
	return nil
}

func shortest(lits []literal) int {
	n := -1
	for _, l := range lits {
		if n < 0 || len(l.s) < n {
			n = len(l.s)
		}
	}
	return n
}

// prefilterText is a text being scanned, with its ASCII lower-cased form
// made on first use.
type prefilterText struct {
	s      string
	lower  string
	ascii  bool
	folded bool
}

func (t *prefilterText) fold() {
	if t.folded {
		return
	}
	t.folded = true
	t.ascii = true
	for i := 0; i < len(t.s); i++ {
		if t.s[i] >= utf8.RuneSelf {
			t.ascii = false
			return
		}
	}
	t.lower = strings.ToLower(t.s)
}

// mayMatch reports whether a rule with the required literals lits can
// match the text: false only when the text contains none of them.
func (t *prefilterText) mayMatch(lits []literal) bool {
	if lits == nil {
		return true
	}
	for _, l := range lits {
		if !l.fold {
			if strings.Contains(t.s, l.s) {
				return true
			}
			continue
		}
		t.fold()
		if !t.ascii || strings.Contains(t.lower, l.s) {
			return true
		}
	}
	return false
}

// classRun is a pattern that is one character class repeated at least min
// times and without an upper bound, such as `[A-Za-z0-9+/_=-]{24,}`. Its
// leftmost-first matches are the maximal runs of class characters at least
// min code points long, which a loop over the text finds without the
// regexp's NFA (a 64 KiB token is one run).
type classRun struct {
	min    int
	ascii  [utf8.RuneSelf]bool
	ranges []rune // the class as lo-hi pairs, for non-ASCII code points
}

// classRunOf returns the classRun of pattern, or nil when pattern is not
// of that form.
func classRunOf(pattern string) *classRun {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	min := 0
	switch {
	case re.Op == syntax.OpPlus:
		min = 1
	case re.Op == syntax.OpRepeat && re.Max == -1 && re.Min >= 1:
		min = re.Min
	default:
		return nil
	}
	if re.Flags&syntax.NonGreedy != 0 {
		return nil
	}
	cl := re.Sub[0]
	if cl.Op != syntax.OpCharClass {
		return nil
	}
	c := &classRun{min: min, ranges: cl.Rune}
	for b := rune(0); b < utf8.RuneSelf; b++ {
		c.ascii[b] = c.has(b)
	}
	return c
}

func (c *classRun) has(r rune) bool {
	for i := 0; i+1 < len(c.ranges); i += 2 {
		if r >= c.ranges[i] && r <= c.ranges[i+1] {
			return true
		}
	}
	return false
}

// findAll returns the byte offsets of the runs, as FindAllStringIndex does
// for the pattern. Invalid UTF-8 decodes to U+FFFD, as in the regexp.
func (c *classRun) findAll(s string) [][]int {
	var out [][]int
	start, n := -1, 0
	for i := 0; i < len(s); {
		r, w := rune(s[i]), 1
		in := false
		if r < utf8.RuneSelf {
			in = c.ascii[r]
		} else {
			r, w = utf8.DecodeRuneInString(s[i:])
			in = c.has(r)
		}
		if in {
			if start < 0 {
				start, n = i, 0
			}
			n++
		} else if start >= 0 {
			if n >= c.min {
				out = append(out, []int{start, i})
			}
			start = -1
		}
		i += w
	}
	if start >= 0 && n >= c.min {
		out = append(out, []int{start, len(s)})
	}
	return out
}

// findAll is FindAllStringIndex of the rule's pattern.
func (r *Rule) findAll(s string) [][]int {
	if r.run != nil {
		return r.run.findAll(s)
	}
	return r.re.FindAllStringIndex(s, -1)
}
