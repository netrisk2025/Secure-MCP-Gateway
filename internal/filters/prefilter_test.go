package filters

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// TestRequiredLiterals: the literal sets of representative patterns, and
// no set where a match can avoid every literal.
func TestRequiredLiterals(t *testing.T) {
	for _, c := range []struct {
		pattern string
		want    []string // nil: no set
	}{
		{`abc`, []string{"abc"}},
		{`(?i)AbC`, []string{"abc/i"}},
		{`\bgh[pousr]_[A-Za-z0-9]{36}\b`, []string{"gh"}},
		{`(?:foo|barbaz)\d+`, []string{"foo", "barbaz"}},
		{`(?:foo|)x`, []string{"x"}},
		{`(?:foo|)`, nil},
		{`(?:foo)?`, nil},
		{`(?:foo)*bar`, []string{"bar"}},
		{`(?:foo)+`, []string{"foo"}},
		{`(?:foo){0,3}`, nil},
		{`(?:foo){2,3}`, []string{"foo"}},
		{`[a-z]{24,}`, nil},
		{`.*`, nil},
		{`(?i)straße`, nil}, // a non-ASCII fold literal
		{`straße`, []string{"straße"}},
		{`a|b[0-9]`, []string{"a", "b"}},
	} {
		lits := requiredLiterals(c.pattern)
		var got []string
		for _, l := range lits {
			s := l.s
			if l.fold {
				s += "/i"
			}
			got = append(got, s)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") || (lits == nil) != (c.want == nil) {
			t.Errorf("%s: literals %q, want %q", c.pattern, got, c.want)
		}
	}
}

// TestPrefilterNeverSkipsAMatch: for every rule of the embedded library,
// on the corpus samples, on case and Unicode variants of them and on
// random texts built from the rule's literals and pattern fragments, the
// prefilter lets the regexp run whenever the regexp matches.
func TestPrefilterNeverSkipsAMatch(t *testing.T) {
	lib, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, name := range []string{"pii.jsonl", "prompt-injection.jsonl", "secret-formats.jsonl", "tool-metadata.jsonl", "unicode-control.jsonl"} {
		for _, s := range loadCorpus(t, name) {
			texts = append(texts, s.Text, strings.ToUpper(s.Text), strings.ToLower(s.Text), swapCase(s.Text), "\u212a"+s.Text, strings.ReplaceAll(s.Text, "s", "\u017f"))
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	alphabet := []string{" ", "a", "Z", "0", "9", "_", "-", ".", "@", "/", ":", "=", "\n", "é", "\u212a", "\u017f", "<", "|", ">", "[", "]"}
	checked := 0
	for _, rs := range lib.All() {
		for _, r := range rs.Rules {
			if r.re == nil {
				continue
			}
			local := append([]string(nil), texts...)
			for range 300 {
				var b strings.Builder
				for range 1 + rng.IntN(12) {
					switch {
					case len(r.lits) > 0 && rng.IntN(3) == 0:
						l := r.lits[rng.IntN(len(r.lits))].s
						if rng.IntN(2) == 0 {
							l = strings.ToUpper(l)
						}
						b.WriteString(l)
					default:
						for range 1 + rng.IntN(8) {
							b.WriteString(alphabet[rng.IntN(len(alphabet))])
						}
					}
				}
				local = append(local, b.String())
			}
			for _, text := range local {
				subject := text
				if rs.Normalize {
					subject = normalizeText(text)
				}
				pf := &prefilterText{s: subject}
				if r.re.MatchString(subject) && !pf.mayMatch(r.lits) {
					t.Fatalf("%s/%s: the prefilter skips a match in %q (literals %v)", rs.ID, r.ID, subject, r.lits)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("nothing checked")
	}
}

// TestPrefilterSkipsRulesOnPlainText: on the FR-11 reference result (64 KiB
// of hexadecimal digits) the prefilter skips every rule that has a literal
// set, and the scan finds what the regexps alone find.
func TestPrefilterSkipsRulesOnPlainText(t *testing.T) {
	lib, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Repeat("0123456789abcdef", 64<<10/16)
	pf := &prefilterText{s: text}
	skipped := 0
	for _, rs := range lib.All() {
		for _, r := range rs.Rules {
			if r.re != nil && r.lits != nil {
				if pf.mayMatch(r.lits) {
					t.Errorf("%s/%s: literals %v found in the reference text", rs.ID, r.ID, r.lits)
				}
				skipped++
			}
		}
		var direct []Match
		for _, r := range rs.Rules {
			direct = append(direct, r.scan(text)...)
		}
		if got := rs.Scan(text); len(got) != len(direct) {
			t.Errorf("%s: %d matches with the prefilter, %d without", rs.ID, len(got), len(direct))
		}
	}
	if skipped < 40 {
		t.Fatalf("only %d rules have literal sets", skipped)
	}
	// A non-ASCII text runs every rule with a fold literal.
	pf = &prefilterText{s: "\u212aey"}
	if !pf.mayMatch([]literal{{"key", true}}) {
		t.Fatal("a non-ASCII text skipped a fold literal")
	}
	if !regexp.MustCompile(`(?i)key`).MatchString("\u212aey") {
		t.Fatal("Kelvin sign does not fold to k")
	}
}

// randomText is a random mix of ASCII, non-ASCII, format characters and
// invalid UTF-8.
func randomText(rng *rand.Rand, n int) string {
	pieces := []string{"a", "Z", "0", "9", "+", "/", "_", "=", "-", " ", "\t", "\n", "\v", "\r", "é", "\u212a", "\u200b", "\u202e", "\xff", "\u3000", "\uff21", "ß", ".", "x"}
	var b strings.Builder
	for range n {
		b.WriteString(pieces[rng.IntN(len(pieces))])
	}
	return b.String()
}

// TestClassRunMatchesRegexp: for patterns that are one character class
// repeated without an upper bound, the run scanner finds what the regexp
// finds, on random text with non-ASCII code points and invalid UTF-8;
// other patterns get no run scanner.
func TestClassRunMatchesRegexp(t *testing.T) {
	for _, p := range []string{`(?i)[A-Za-z0-9+/_=-]{24,}`, `[A-Za-z0-9+/_=-]{24,}`, `(?i)[a-f0-9]{3,}`, `[0-9]+`, `\d{2,}`, `[^ ]{5,}`, `(?:[a-z]{4,})`, `[\x{FFFD}a]{2,}`} {
		c := classRunOf(p)
		if c == nil {
			t.Fatalf("%s: no run scanner", p)
		}
		re := regexp.MustCompile(p)
		rng := rand.New(rand.NewPCG(3, 4))
		for i := range 2000 {
			s := randomText(rng, rng.IntN(80))
			if i%50 == 0 {
				s = strings.Repeat("0123456789abcdef", 64)
			}
			got, want := c.findAll(s), re.FindAllStringIndex(s, -1)
			if len(got) != len(want) {
				t.Fatalf("%s on %q: %v, regexp %v", p, s, got, want)
			}
			for j := range got {
				if got[j][0] != want[j][0] || got[j][1] != want[j][1] {
					t.Fatalf("%s on %q: %v, regexp %v", p, s, got, want)
				}
			}
		}
	}
	for _, p := range []string{`[a-z]{2,5}`, `[a-z]+?`, `ab+`, `[a-z]*`, `a{3,}b`, `(?:ab){2,}`} {
		if classRunOf(p) != nil {
			t.Errorf("%s: run scanner for a pattern that is not one repeated class", p)
		}
	}
}

// normalizeReference is normalizeText without its ASCII path.
func normalizeReference(s string) string {
	s = norm.NFKC.String(s)
	var b strings.Builder
	space := false
	for _, c := range s {
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

// TestNormalizeTextASCIIPath: the ASCII path of normalizeText gives the
// text the rune-by-rune definition gives.
func TestNormalizeTextASCIIPath(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	texts := []string{"", "Ignore   PREVIOUS\tInstructions\n\n", strings.Repeat("0123456789abcdef", 4096)}
	for range 3000 {
		texts = append(texts, randomText(rng, rng.IntN(60)))
	}
	for b := 0; b < 128; b++ {
		texts = append(texts, "a"+string(rune(b))+"B")
	}
	for _, s := range texts {
		if got, want := normalizeText(s), normalizeReference(s); got != want {
			t.Fatalf("normalizeText(%q) = %q, want %q", s, got, want)
		}
	}
}

func swapCase(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// BenchmarkRuleSetScan64K scans the FR-11 reference result with every
// embedded rule set, with the prefilter, the ASCII path of code point
// rules and the class-run scanner and, for comparison, without them (the
// normalization of phrase rule sets is the same in both).
func BenchmarkRuleSetScan64K(b *testing.B) {
	lib, err := LoadEmbedded()
	if err != nil {
		b.Fatal(err)
	}
	text := strings.Repeat("0123456789abcdef", 64<<10/16)
	scan := func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, rs := range lib.All() {
				rs.Scan(text)
			}
		}
	}
	b.Run("prefilter", scan)
	b.Run("regexp-only", func(b *testing.B) {
		type saved struct {
			lits  []literal
			ascii bool
			run   *classRun
		}
		keep := map[*Rule]saved{}
		for _, rs := range lib.All() {
			for _, r := range rs.Rules {
				keep[r] = saved{r.lits, r.asciiFree, r.run}
				r.lits, r.asciiFree, r.run = nil, false, nil
			}
		}
		defer func() {
			for r, k := range keep {
				r.lits, r.asciiFree, r.run = k.lits, k.ascii, k.run
			}
		}()
		scan(b)
	})
}
