package filters

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Rule-set IDs the built-in filters load (FR-4.16).
const (
	RuleSetUnicode   = "unicode-control"
	RuleSetSecrets   = "secret-formats"
	RuleSetInjection = "prompt-injection"
	RuleSetPII       = "pii"
	RuleSetMetadata  = "tool-metadata"
)

// RequiredRuleSets are the rule sets a usable index must provide.
var RequiredRuleSets = []string{RuleSetUnicode, RuleSetSecrets, RuleSetInjection, RuleSetPII, RuleSetMetadata}

// Rule actions. On the response side "block" withholds the result.
const (
	ActionBlock  = "block"
	ActionRedact = "redact"
	ActionTag    = "tag"
)

//go:embed rules/*.json
var embedded embed.FS

// Index is rules/index.json: every rule-set file with its version, SHA-256
// digest, labelled corpus and the error-rate targets its corpus must meet
// (FR-19.5).
type Index struct {
	SchemaVersion int          `json:"schema_version"`
	RuleSets      []IndexEntry `json:"rule_sets"`
}

// IndexEntry names one rule-set file.
type IndexEntry struct {
	ID      string  `json:"id"`
	Version string  `json:"version"`
	File    string  `json:"file"`
	SHA256  string  `json:"sha256"`
	Active  bool    `json:"active"`
	Corpus  string  `json:"corpus,omitempty"`
	Targets Targets `json:"targets"`
}

// Targets are the documented maximum error rates of a rule-set version
// against its corpus.
type Targets struct {
	FalsePositiveRate float64 `json:"false_positive_rate"`
	FalseNegativeRate float64 `json:"false_negative_rate"`
}

// RuleSet is one loaded, digest-checked rule-set version.
type RuleSet struct {
	ID          string  `json:"id"`
	Version     string  `json:"version"`
	Description string  `json:"description,omitempty"`
	Normalize   bool    `json:"normalize,omitempty"` // match on normalized text (no redaction offsets)
	Rules       []*Rule `json:"rules"`

	Digest  string  `json:"-"`
	Targets Targets `json:"-"`
	Corpus  string  `json:"-"`
}

// Rule is one detection rule. Kind selects the matcher:
//
//	regex       Pattern (RE2), case-insensitive unless CaseSensitive
//	luhn        Pattern whose digits must also pass the Luhn check
//	entropy     Pattern selects candidate tokens; a token matches when it
//	            is at least MinLength long, has MinClasses character classes
//	            and Shannon entropy of at least MinEntropy bits per symbol
//	codepoints  Ranges of code points, with the permitted contexts below
type Rule struct {
	ID             string  `json:"id"`
	Kind           string  `json:"kind"`
	Description    string  `json:"description,omitempty"`
	Pattern        string  `json:"pattern,omitempty"`
	CaseSensitive  bool    `json:"case_sensitive,omitempty"`
	RequestAction  string  `json:"request_action"`
	ResponseAction string  `json:"response_action"`
	Score          float64 `json:"score,omitempty"`

	MinLength  int     `json:"min_length,omitempty"`
	MinEntropy float64 `json:"min_entropy,omitempty"`
	MinClasses int     `json:"min_classes,omitempty"`

	Ranges           []string `json:"ranges,omitempty"`            // "202A-202E" or "200B"
	PermittedScripts []string `json:"permitted_scripts,omitempty"` // Unicode script names (Go unicode.Scripts)
	PermitEmoji      bool     `json:"permit_emoji,omitempty"`      // between pictographic characters
	PermitAfter      []string `json:"permit_after,omitempty"`      // ranges that may precede a run (tag sequences)
	PermitAtStart    bool     `json:"permit_at_start,omitempty"`   // e.g. a byte-order mark

	re     *regexp.Regexp
	lits   []literal // one of them is in every match of re (nil: unknown)
	run    *classRun // re is one character class repeated (nil: not)
	ranges *unicode.RangeTable
	// asciiFree: no ASCII code point is in ranges, so a codepoints scan
	// passes over ASCII bytes without decoding them.
	asciiFree bool
	scripts   []*unicode.RangeTable
	after     *unicode.RangeTable
}

var idPat = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// LoadEmbedded loads the rule sets compiled into the binary.
func LoadEmbedded() (*Library, error) {
	sub, err := fs.Sub(embedded, "rules")
	if err != nil {
		return nil, err
	}
	return LoadFS(sub)
}

// LoadDir loads rule sets from a directory holding index.json.
func LoadDir(dir string) (*Library, error) { return LoadFS(os.DirFS(dir)) }

// Library holds every rule-set version an index lists.
type Library struct {
	Index    Index
	versions map[string]map[string]*RuleSet // id -> version -> set
	active   map[string]string
}

// LoadFS loads and verifies every rule set of fsys/index.json. A file whose
// SHA-256 differs from its index entry, an unparseable rule or a missing
// required rule set refuses the whole library (FR-4.16).
func LoadFS(fsys fs.FS) (*Library, error) {
	raw, err := fs.ReadFile(fsys, "index.json")
	if err != nil {
		return nil, fmt.Errorf("rule index: %w", err)
	}
	lib := &Library{versions: map[string]map[string]*RuleSet{}, active: map[string]string{}}
	if err := strictUnmarshal(raw, &lib.Index); err != nil {
		return nil, fmt.Errorf("rule index: %w", err)
	}
	if lib.Index.SchemaVersion != 1 {
		return nil, fmt.Errorf("rule index: schema_version %d is not supported", lib.Index.SchemaVersion)
	}
	for _, e := range lib.Index.RuleSets {
		if !idPat.MatchString(e.ID) || e.Version == "" || path.Base(e.File) != e.File {
			return nil, fmt.Errorf("rule index: bad entry %q version %q file %q", e.ID, e.Version, e.File)
		}
		body, err := fs.ReadFile(fsys, e.File)
		if err != nil {
			return nil, fmt.Errorf("rule set %s %s: %w", e.ID, e.Version, err)
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != e.SHA256 {
			return nil, fmt.Errorf("rule set %s %s: file %s has digest %s, index says %s", e.ID, e.Version, e.File, got, e.SHA256)
		}
		rs, err := parseRuleSet(body)
		if err != nil {
			return nil, fmt.Errorf("rule set %s %s: %w", e.ID, e.Version, err)
		}
		if rs.ID != e.ID || rs.Version != e.Version {
			return nil, fmt.Errorf("rule set file %s declares %s %s, index says %s %s", e.File, rs.ID, rs.Version, e.ID, e.Version)
		}
		rs.Digest, rs.Targets, rs.Corpus = e.SHA256, e.Targets, e.Corpus
		if lib.versions[e.ID] == nil {
			lib.versions[e.ID] = map[string]*RuleSet{}
		}
		if lib.versions[e.ID][e.Version] != nil {
			return nil, fmt.Errorf("rule index: %s %s listed twice", e.ID, e.Version)
		}
		lib.versions[e.ID][e.Version] = rs
		if e.Active {
			if prev, dup := lib.active[e.ID]; dup {
				return nil, fmt.Errorf("rule index: %s has two active versions (%s, %s)", e.ID, prev, e.Version)
			}
			lib.active[e.ID] = e.Version
		}
	}
	for _, id := range RequiredRuleSets {
		if lib.active[id] == "" {
			return nil, fmt.Errorf("rule index: no active version of required rule set %s", id)
		}
	}
	return lib, nil
}

func strictUnmarshal(raw []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Get returns the rule set id at version, or the active version when
// version is empty.
func (l *Library) Get(id, version string) (*RuleSet, error) {
	if version == "" {
		version = l.active[id]
	}
	rs := l.versions[id][version]
	if rs == nil {
		return nil, fmt.Errorf("rule set %s version %q is not in the index", id, version)
	}
	return rs, nil
}

// All returns every loaded rule-set version, sorted by ID and version.
func (l *Library) All() []*RuleSet {
	var out []*RuleSet
	for _, vs := range l.versions {
		for _, rs := range vs {
			out = append(out, rs)
		}
	}
	slices.SortFunc(out, func(a, b *RuleSet) int {
		if c := strings.Compare(a.ID, b.ID); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return out
}

// ActiveVersion returns the version marked active in the index.
func (l *Library) ActiveVersion(id string) string { return l.active[id] }

func parseRuleSet(body []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := strictUnmarshal(body, &rs); err != nil {
		return nil, err
	}
	if !idPat.MatchString(rs.ID) || rs.Version == "" || len(rs.Rules) == 0 {
		return nil, errors.New("id, version and at least one rule are required")
	}
	seen := map[string]bool{}
	for _, r := range rs.Rules {
		if !idPat.MatchString(r.ID) || seen[r.ID] {
			return nil, fmt.Errorf("rule ID %q invalid or duplicated", r.ID)
		}
		seen[r.ID] = true
		if err := r.compile(rs.Normalize); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
	}
	return &rs, nil
}

func validAction(a string) bool { return a == ActionBlock || a == ActionRedact || a == ActionTag }

func (r *Rule) compile(normalized bool) error {
	if !validAction(r.RequestAction) || !validAction(r.ResponseAction) {
		return fmt.Errorf("request_action %q and response_action %q must be block, redact or tag", r.RequestAction, r.ResponseAction)
	}
	if normalized && (r.RequestAction == ActionRedact || r.ResponseAction == ActionRedact) {
		return errors.New("rules of a normalized rule set cannot redact")
	}
	if r.Score == 0 {
		r.Score = 1
	}
	switch r.Kind {
	case "regex", "luhn", "entropy":
		if r.Pattern == "" {
			return errors.New("pattern is required")
		}
		p := r.Pattern
		if !r.CaseSensitive {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		r.re = re
		r.lits = requiredLiterals(p)
		r.run = classRunOf(p)
		if r.Kind == "entropy" && (r.MinLength <= 0 || r.MinEntropy <= 0) {
			return errors.New("entropy rules need min_length and min_entropy")
		}
	case "codepoints":
		t, err := parseRanges(r.Ranges)
		if err != nil {
			return err
		}
		if t == nil {
			return errors.New("ranges are required")
		}
		r.ranges = t
		r.asciiFree = true
		for c := rune(0); c < utf8.RuneSelf; c++ {
			if unicode.Is(t, c) {
				r.asciiFree = false
				break
			}
		}
		for _, name := range r.PermittedScripts {
			s, ok := unicode.Scripts[name]
			if !ok {
				return fmt.Errorf("unknown script %q", name)
			}
			r.scripts = append(r.scripts, s)
		}
		if r.after, err = parseRanges(r.PermitAfter); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown kind %q", r.Kind)
	}
	return nil
}

func parseRanges(specs []string) (*unicode.RangeTable, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	t := &unicode.RangeTable{}
	for _, s := range specs {
		lo, hi, found := strings.Cut(s, "-")
		if !found {
			hi = lo
		}
		a, err1 := strconv.ParseUint(lo, 16, 32)
		b, err2 := strconv.ParseUint(hi, 16, 32)
		if err1 != nil || err2 != nil || a > b || b > unicode.MaxRune {
			return nil, fmt.Errorf("bad range %q", s)
		}
		// a <= b <= unicode.MaxRune was checked above, so the conversions
		// below cannot overflow.
		if b <= 0xFFFF {
			t.R16 = append(t.R16, unicode.Range16{Lo: uint16(a), Hi: uint16(b), Stride: 1}) //nolint:gosec // bounded above
		} else if a > 0xFFFF {
			t.R32 = append(t.R32, unicode.Range32{Lo: uint32(a), Hi: uint32(b), Stride: 1}) //nolint:gosec // bounded above
		} else {
			t.R16 = append(t.R16, unicode.Range16{Lo: uint16(a), Hi: 0xFFFF, Stride: 1})  //nolint:gosec // bounded above
			t.R32 = append(t.R32, unicode.Range32{Lo: 0x10000, Hi: uint32(b), Stride: 1}) //nolint:gosec // bounded above
		}
	}
	slices.SortFunc(t.R16, func(x, y unicode.Range16) int { return int(x.Lo) - int(y.Lo) })
	slices.SortFunc(t.R32, func(x, y unicode.Range32) int { return int(x.Lo) - int(y.Lo) })
	return t, nil
}

// ExportEmbedded writes the built-in index and rule-set files into dir, as
// the starting point of a custom rules_dir. Existing files are not
// overwritten.
func ExportEmbedded(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(embedded, "rules")
	if err != nil {
		return nil, err
	}
	var written []string
	for _, e := range entries {
		body, err := fs.ReadFile(embedded, "rules/"+e.Name())
		if err != nil {
			return nil, err
		}
		p := filepath.Join(dir, e.Name())
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return written, err
		}
		_, werr := f.Write(body)
		cerr := f.Close()
		if err := errors.Join(werr, cerr); err != nil {
			return written, err
		}
		written = append(written, p)
	}
	return written, nil
}

// AddVersion writes a new version of a rule set into the rules directory
// dir: the rule-set file and an index entry with its SHA-256 digest,
// copying the corpus and targets of the active version. The new version is
// not active; select it with rule_versions or UseRuleSet.
func AddVersion(dir string, rs *RuleSet) error {
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return err
	}
	var idx Index
	if err := strictUnmarshal(raw, &idx); err != nil {
		return err
	}
	var base *IndexEntry
	for i := range idx.RuleSets {
		if idx.RuleSets[i].ID == rs.ID && idx.RuleSets[i].Active {
			base = &idx.RuleSets[i]
		}
	}
	if base == nil {
		return fmt.Errorf("rule set %s has no active version in %s", rs.ID, dir)
	}
	body, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if _, err := parseRuleSet(body); err != nil {
		return err
	}
	file := rs.ID + "." + rs.Version + ".json"
	if err := os.WriteFile(filepath.Join(dir, file), body, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	e := *base
	e.Version, e.File, e.SHA256, e.Active = rs.Version, file, hex.EncodeToString(sum[:]), false
	idx.RuleSets = append(idx.RuleSets, e)
	out, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.json"), append(out, '\n'), 0o644)
}
