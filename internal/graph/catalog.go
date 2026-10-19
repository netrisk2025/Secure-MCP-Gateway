package graph

import (
	"bufio"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// TemplateSetVersion names the version of the operation catalog. It changes
// whenever an operation is added, removed or changes its parameters.
const TemplateSetVersion = "2026-10-16.1"

//go:embed templates/*.cypher templates/MANIFEST.sha256
var embedded embed.FS

// Mode is the transaction mode of an operation.
type Mode string

// Transaction modes.
const (
	ModeRead  Mode = "read"
	ModeWrite Mode = "write"
)

// ParamType is the declared type of a template parameter.
type ParamType string

// Parameter types.
const (
	TypeRows    ParamType = "rows"    // list of row maps built by the service
	TypeString  ParamType = "string"  // bounded string
	TypeInt     ParamType = "int"     // int64
	TypeStrings ParamType = "strings" // list of strings
)

// Op is one typed operation of the catalog with its fixed template. Its
// fields are unexported so that no caller can build an Op with its own
// query text; operations come only from the verified catalog.
type Op struct {
	id     string
	mode   Mode
	params map[string]ParamType
	text   string
}

// ID is the operation ID (for example "neighborhood.Session").
func (o *Op) ID() string { return o.id }

// Mode is the transaction mode.
func (o *Op) Mode() Mode { return o.mode }

// Text is the fixed Cypher template.
func (o *Op) Text() string { return o.text }

// Params lists the declared parameter names in order.
func (o *Op) Params() []string {
	out := make([]string, 0, len(o.params))
	for k := range o.params {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Migration is one ordered schema migration (FR-9.2).
type Migration struct {
	Version int
	Name    string
	Ops     []*Op // one schema statement each, run in its own transaction
}

// Catalog is the verified operation catalog and migration set.
type Catalog struct {
	ops        map[string]*Op
	migrations []Migration
	digest     string // sha256 of MANIFEST.sha256
}

// Errors of the catalog and the Data Access Service.
var (
	ErrTemplateDigest   = errors.New("graph: query template set does not match its manifest")
	ErrUnknownOp        = errors.New("graph: operation is not in the catalog")
	ErrBadParameter     = errors.New("graph: parameter rejected")
	ErrSchemaTooNew     = errors.New("graph: database schema is newer than this release supports")
	ErrUnavailable      = errors.New("graph: database unavailable")
	ErrNotFound         = errors.New("graph: not found")
	ErrDisabled         = errors.New("graph: mirror disabled")
	ErrHardening        = errors.New("graph: database configuration fails the hardening check")
	ErrRebuildRunning   = errors.New("graph: a rebuild is already queued")
	errMalformedCatalog = errors.New("graph: malformed template set")
)

var (
	opHeader    = regexp.MustCompile(`^// op: ([a-z]+(\.[A-Za-z_]+)*)$`)
	migrationFn = regexp.MustCompile(`^([0-9]{4})_([a-z_]+)\.cypher$`)
)

var defaultCatalog = func() *Catalog {
	c, err := LoadCatalog(embedded)
	if err != nil {
		panic(err)
	}
	return c
}()

// DefaultCatalog returns the embedded, verified catalog.
func DefaultCatalog() *Catalog { return defaultCatalog }

// LoadCatalog reads the template set and migrations under templates/ of
// fsys and verifies every file against templates/MANIFEST.sha256
// (SR-1.13-2). A file that is missing from the manifest, listed but absent,
// or whose digest differs is refused.
func LoadCatalog(fsys fs.FS) (*Catalog, error) {
	manifest, err := fs.ReadFile(fsys, "templates/MANIFEST.sha256")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTemplateDigest, err)
	}
	want := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || len(f[0]) != 64 {
			return nil, fmt.Errorf("%w: bad manifest line %q", ErrTemplateDigest, line)
		}
		want[strings.TrimPrefix(f[1], "*")] = f[0]
	}
	files, err := fs.Glob(fsys, "templates/*.cypher")
	if err != nil {
		return nil, err
	}
	if len(files) != len(want) {
		return nil, fmt.Errorf("%w: %d files, %d manifest entries", ErrTemplateDigest, len(files), len(want))
	}
	c := &Catalog{ops: map[string]*Op{}}
	sum := sha256.Sum256(manifest)
	c.digest = hex.EncodeToString(sum[:])
	for _, name := range files {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		base := path.Base(name)
		got := sha256.Sum256(raw)
		if w, ok := want[base]; !ok || w != hex.EncodeToString(got[:]) {
			return nil, fmt.Errorf("%w: %s", ErrTemplateDigest, base)
		}
		if base == "templates.cypher" {
			if err := c.parseOps(string(raw)); err != nil {
				return nil, err
			}
			continue
		}
		m := migrationFn.FindStringSubmatch(base)
		if m == nil {
			return nil, fmt.Errorf("%w: unexpected file %s", errMalformedCatalog, base)
		}
		v, _ := strconv.Atoi(m[1]) // four digits by the pattern
		mig := Migration{Version: v, Name: m[2]}
		for i, text := range splitStatements(string(raw)) {
			op := &Op{id: fmt.Sprintf("migration.%04d.%02d", v, i+1), mode: ModeWrite, params: map[string]ParamType{}, text: text}
			c.ops[op.id] = op
			mig.Ops = append(mig.Ops, op)
		}
		c.migrations = append(c.migrations, mig)
	}
	sort.Slice(c.migrations, func(i, k int) bool { return c.migrations[i].Version < c.migrations[k].Version })
	for i, m := range c.migrations {
		if m.Version != i+1 {
			return nil, fmt.Errorf("%w: migrations must be numbered 1..n without gaps", errMalformedCatalog)
		}
	}
	if len(c.ops) == 0 {
		return nil, fmt.Errorf("%w: no operations", errMalformedCatalog)
	}
	return c, nil
}

func (c *Catalog) parseOps(src string) error {
	var cur *Op
	var body []string
	flush := func() error {
		if cur == nil {
			return nil
		}
		cur.text = strings.TrimSpace(strings.Join(body, "\n"))
		if cur.text == "" || cur.mode == "" {
			return fmt.Errorf("%w: op %s lacks mode or text", errMalformedCatalog, cur.id)
		}
		if _, dup := c.ops[cur.id]; dup {
			return fmt.Errorf("%w: duplicate op %s", errMalformedCatalog, cur.id)
		}
		c.ops[cur.id] = cur
		cur, body = nil, nil
		return nil
	}
	sc := bufio.NewScanner(strings.NewReader(src))
	for sc.Scan() {
		line := sc.Text()
		if m := opHeader.FindStringSubmatch(line); m != nil {
			if err := flush(); err != nil {
				return err
			}
			cur = &Op{id: m[1], params: map[string]ParamType{}}
			continue
		}
		if cur == nil {
			continue // file header comments
		}
		switch {
		case strings.HasPrefix(line, "// mode: "):
			cur.mode = Mode(strings.TrimPrefix(line, "// mode: "))
			if cur.mode != ModeRead && cur.mode != ModeWrite {
				return fmt.Errorf("%w: op %s mode %q", errMalformedCatalog, cur.id, cur.mode)
			}
		case strings.HasPrefix(line, "// params:"):
			for _, p := range strings.Fields(strings.TrimPrefix(line, "// params:")) {
				name, typ, ok := strings.Cut(p, ":")
				switch ParamType(typ) {
				case TypeRows, TypeString, TypeInt, TypeStrings:
				default:
					ok = false
				}
				if !ok {
					return fmt.Errorf("%w: op %s param %q", errMalformedCatalog, cur.id, p)
				}
				cur.params[name] = ParamType(typ)
			}
		case strings.HasPrefix(line, "//"):
		default:
			body = append(body, line)
		}
	}
	return flush()
}

func splitStatements(src string) []string {
	var lines []string
	for _, l := range strings.Split(src, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "//") {
			lines = append(lines, l)
		}
	}
	var out []string
	for _, s := range strings.Split(strings.Join(lines, "\n"), ";") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Op returns the operation with the given ID.
func (c *Catalog) Op(id string) (*Op, error) {
	if op, ok := c.ops[id]; ok {
		return op, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownOp, id)
}

// Ops lists the operation IDs in order.
func (c *Catalog) Ops() []string {
	out := make([]string, 0, len(c.ops))
	for id := range c.ops {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Migrations returns the ordered migrations.
func (c *Catalog) Migrations() []Migration { return append([]Migration(nil), c.migrations...) }

// SchemaVersion is the newest schema version this release supports.
func (c *Catalog) SchemaVersion() int { return len(c.migrations) }

// Digest is the SHA-256 of the template manifest.
func (c *Catalog) Digest() string { return c.digest }

// Statement is one operation with its parameters.
type Statement struct {
	Op     *Op
	Params map[string]any
}

// Row is one result record.
type Row map[string]any

// Bounds on parameter values.
const (
	MaxStringParam = 512
	MaxRows        = 5000
	MaxLimit       = 500
)

// Validate checks params against the operation's declaration: exactly the
// declared names, the declared types, bounded strings and row counts. It is
// the check that refuses caller-supplied query text in any other shape
// (SR-1.13-1); values are only ever bound as parameters.
func (o *Op) Validate(params map[string]any) error {
	for name := range params {
		if _, ok := o.params[name]; !ok {
			return fmt.Errorf("%w: %s does not take %q", ErrBadParameter, o.id, name)
		}
	}
	for name, typ := range o.params {
		v, ok := params[name]
		if !ok {
			return fmt.Errorf("%w: %s needs %q", ErrBadParameter, o.id, name)
		}
		switch typ {
		case TypeString:
			s, ok := v.(string)
			if !ok || len(s) > MaxStringParam || strings.ContainsFunc(s, isControl) {
				return fmt.Errorf("%w: %s.%s must be a string of at most %d bytes without control characters", ErrBadParameter, o.id, name, MaxStringParam)
			}
		case TypeInt:
			if _, ok := v.(int64); !ok {
				return fmt.Errorf("%w: %s.%s must be int64", ErrBadParameter, o.id, name)
			}
		case TypeStrings:
			l, ok := v.([]string)
			if !ok || len(l) > 64 {
				return fmt.Errorf("%w: %s.%s must be a short list of strings", ErrBadParameter, o.id, name)
			}
		case TypeRows:
			rows, ok := v.([]map[string]any)
			if !ok || len(rows) == 0 || len(rows) > MaxRows {
				return fmt.Errorf("%w: %s.%s must hold 1..%d rows", ErrBadParameter, o.id, name, MaxRows)
			}
		}
	}
	if l, ok := params["limit"].(int64); ok && (l < 1 || l > 10000) {
		return fmt.Errorf("%w: limit out of range", ErrBadParameter)
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }
