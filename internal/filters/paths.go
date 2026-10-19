package filters

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// PathOptions configure path-canonicalize (SR-1.8-4).
type PathOptions struct {
	Roots       []string            // granted roots for every server
	ServerRoots map[string][]string // granted roots per server alias (replace Roots)
	Names       []string            // extra property names treated as paths
	IgnoreNames []string            // property names never treated as paths
	Rewrite     bool                // replace arguments with their canonical form
}

type pathFilter struct {
	opts  PathOptions
	kind  argKind
	roots map[string][]string // canonical; "" = all servers
}

var errNoRoot = errors.New("root does not exist")

func newPathFilter(o PathOptions) (*pathFilter, error) {
	f := &pathFilter{opts: o, kind: withNames(pathKind, o.Names), roots: map[string][]string{}}
	canon := func(list []string) ([]string, error) {
		var out []string
		for _, r := range list {
			if !filepath.IsAbs(r) {
				return nil, errors.New("granted root " + r + " is not absolute")
			}
			c, err := filepath.EvalSymlinks(filepath.Clean(r))
			if err != nil {
				return nil, errors.Join(errNoRoot, err)
			}
			out = append(out, c)
		}
		return out, nil
	}
	var err error
	if f.roots[""], err = canon(o.Roots); err != nil {
		return nil, err
	}
	for alias, list := range o.ServerRoots {
		if f.roots[alias], err = canon(list); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (f *pathFilter) ID() string      { return IDPathCanonicalize }
func (f *pathFilter) Version() string { return filterVersion }

func (f *pathFilter) rootsFor(server string) []string {
	if r, ok := f.roots[server]; ok {
		return r
	}
	return f.roots[""]
}

func (f *pathFilter) FilterRequest(_ context.Context, call *pipeline.Call, args json.RawMessage) (pipeline.RequestVerdict, error) {
	v, _, ok := argSurfaces(args)
	if !ok {
		return invalidArguments(), nil
	}
	roots, granted := narrowRoots(f.rootsFor(call.Server), call.Project)
	changed := false
	var findings []pipeline.Finding
	for _, ts := range typedSurfaces(call.InputSchema, v, f.kind) {
		if slices.Contains(f.opts.IgnoreNames, ts.name) {
			continue
		}
		canon, rule := CanonicalPath(ts.get(), roots)
		if !granted {
			rule = "project-outside-roots" // FR-2.7: nothing is left to grant
		}
		if rule != "" {
			fd := pipeline.Finding{Filter: IDPathCanonicalize, Rule: rule, Location: ts.loc}
			reason := ReasonPathInvalid
			if rule == "outside-roots" || rule == "project-outside-roots" {
				reason = ReasonPathOutsideRoots
			}
			return pipeline.RequestVerdict{Action: pipeline.Block, ReasonCode: reason, Finding: "path argument at " + ts.loc + ": " + pathRuleText[rule], Findings: []pipeline.Finding{fd}}, nil
		}
		// Rewriting needs granted roots: without them there is no
		// containment to protect, and a server's own lexical root checks
		// could be confused by a resolved form.
		if f.opts.Rewrite && len(roots) > 0 && canon != ts.get() {
			ts.set(canon)
			changed = true
			findings = append(findings, pipeline.Finding{Filter: IDPathCanonicalize, Rule: "canonicalized", Location: ts.loc})
		}
	}
	if !changed {
		return pipeline.RequestVerdict{Action: pipeline.Pass}, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return pipeline.RequestVerdict{}, err
	}
	return pipeline.RequestVerdict{Action: pipeline.Transform, Arguments: raw, Findings: findings}, nil
}

// narrowRoots applies a session's project-root claim to the granted roots
// (FR-2.7): the project root replaces every granted root that contains it,
// and a granted root inside the project root is kept. With no granted roots
// the project root becomes the only root. A project root that is relative,
// does not resolve, or meets no granted root leaves nothing granted, and ok
// is false so that every path argument is refused.
func narrowRoots(roots []string, project string) ([]string, bool) {
	if project == "" {
		return roots, true
	}
	if !filepath.IsAbs(project) {
		return nil, false
	}
	p, err := filepath.EvalSymlinks(filepath.Clean(project))
	if err != nil {
		return nil, false
	}
	if len(roots) == 0 {
		return []string{p}, true
	}
	var out []string
	for _, r := range roots {
		switch {
		case within(p, r):
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		case within(r, p):
			out = append(out, r)
		}
	}
	return out, len(out) > 0
}

// within reports whether path p is root or lies under it.
func within(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

var pathRuleText = map[string]string{
	"nul-byte":              "contains a NUL byte",
	"encoded-separator":     "contains a percent-encoded separator or dot",
	"backslash-dots":        "contains a backslash traversal",
	"home-relative":         "starts with ~ and would be expanded by the server",
	"bad-file-url":          "is a file URL that cannot be parsed or names a host",
	"outside-roots":         "resolves outside the granted roots",
	"project-outside-roots": "cannot be used: the session's project root is not inside the granted roots",
	"relative-no-root":      "is relative and escapes the working directory",
}

// CanonicalPath resolves p against roots: a relative path is joined to the
// first root, ".", ".." and symbolic links are resolved (the longest
// existing prefix is resolved, the rest appended), and the result must lie
// inside one root. With no roots, an absolute path is resolved and
// returned and a relative path is cleaned and must not climb out of the
// working directory. The second result names the violated rule, or is
// empty.
func CanonicalPath(p string, roots []string) (string, string) {
	if strings.ContainsRune(p, 0) {
		return "", "nul-byte"
	}
	low := strings.ToLower(p)
	for _, enc := range []string{"%2f", "%5c", "%2e", "%00", "%25"} {
		if strings.Contains(low, enc) && !strings.HasPrefix(low, "file:") {
			return "", "encoded-separator"
		}
	}
	if strings.HasPrefix(low, "file:") {
		if strings.Contains(low, "%2f") || strings.Contains(low, "%5c") || strings.Contains(low, "%00") {
			return "", "encoded-separator"
		}
		u, err := url.Parse(p)
		if err != nil || (u.Host != "" && u.Host != "localhost") || u.Path == "" {
			return "", "bad-file-url"
		}
		p = u.Path
	}
	if strings.Contains(p, `..\`) || strings.Contains(p, `\..`) {
		return "", "backslash-dots"
	}
	if strings.HasPrefix(p, "~") && len(roots) > 0 {
		return "", "home-relative"
	}
	if !filepath.IsAbs(p) {
		if len(roots) == 0 {
			c := filepath.Clean(p)
			if c == ".." || strings.HasPrefix(c, "../") {
				return "", "relative-no-root"
			}
			return c, ""
		}
		p = filepath.Join(roots[0], p)
	}
	c := resolveExisting(filepath.Clean(p))
	if len(roots) == 0 {
		return c, ""
	}
	for _, r := range roots {
		if c == r || strings.HasPrefix(c, strings.TrimSuffix(r, string(filepath.Separator))+string(filepath.Separator)) {
			return c, ""
		}
	}
	return "", "outside-roots"
}

// resolveExisting resolves symbolic links in the longest existing prefix of
// an absolute, clean path and appends the remainder.
func resolveExisting(p string) string { return resolveDepth(p, 0) }

func resolveDepth(p string, hops int) string {
	rest := ""
	cur := p
	for {
		// A dangling symbolic link resolves to its target, so that a write
		// through it cannot leave the roots.
		if fi, err := os.Lstat(cur); err == nil && fi.Mode()&fs.ModeSymlink != 0 && hops < 40 {
			if _, err := os.Stat(cur); errors.Is(err, fs.ErrNotExist) {
				if t, err := os.Readlink(cur); err == nil {
					if !filepath.IsAbs(t) {
						t = filepath.Join(filepath.Dir(cur), t)
					}
					r := resolveDepth(filepath.Clean(t), hops+1)
					if rest == "" {
						return r
					}
					return filepath.Join(r, rest)
				}
			}
		}
		r, err := filepath.EvalSymlinks(cur)
		if err == nil {
			if rest == "" {
				return r
			}
			return filepath.Join(r, rest)
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, os.ErrNotExist) {
			// Permission or loop errors: keep the lexical form; containment
			// is still checked on it.
			return p
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}
