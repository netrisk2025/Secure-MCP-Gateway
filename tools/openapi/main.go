// Command openapi writes the OpenAPI 3.1 document of the control API
// (FR-8.1) to a file, without starting the Gateway, for the project site.
//
//	go run ./tools/openapi                 # writes site/data/openapi.json
//	go run ./tools/openapi -check          # exit 1 when the file is stale
//
// The operations come from internal/openapi (the table that smcpd serves at
// GET /api/v1/openapi.json). The roles of each operation come from the
// route registrations in the Go sources: every call of Handle, HandleRoles
// or HandlePublic with a literal "METHOD /api/v1/..." or "/admin/v1/..."
// pattern, resolved through adminapi.DescribeRoute exactly as registration
// resolves it. The served document and this file therefore state the same
// roles.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/openapi"
)

// DefaultOut is where the site reads the document.
const DefaultOut = "site/data/openapi.json"

var routeLiteral = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE) /(api|admin)/v1/[A-Za-z0-9_./{}-]*$`)

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("o", DefaultOut, "output file, relative to -root unless absolute")
	check := flag.Bool("check", false, "compare with the existing file instead of writing it")
	flag.Parse()
	if err := run(*root, *out, *check); err != nil {
		fmt.Fprintln(os.Stderr, "openapi:", err)
		os.Exit(1)
	}
}

func run(root, out string, check bool) error {
	doc, err := Generate(root)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(out) {
		out = filepath.Join(root, out)
	}
	if check {
		cur, err := os.ReadFile(out) // #nosec G304 -- operator-supplied path
		if err != nil {
			return err
		}
		if !bytes.Equal(cur, doc) {
			return fmt.Errorf("%s is stale; run `make openapi` (go run ./tools/openapi) and commit it", out)
		}
		return nil
	}
	return os.WriteFile(out, doc, 0o644) // #nosec G306 -- a public document
}

// Generate returns the document as indented JSON with a trailing newline.
func Generate(root string) ([]byte, error) {
	routes, err := SourceRoutes(root)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", " ")
	if err := enc.Encode(openapi.Document(routes)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// SourceRoutes finds every control API route registration in the non-test
// Go files under internal/ and cmd/ and describes it as registration would.
// The OpenAPI route itself is registered by internal/openapi with Handle.
func SourceRoutes(root string) ([]adminapi.RouteInfo, error) {
	roleNames, err := roleConstants(filepath.Join(root, "internal", "adminapi"))
	if err != nil {
		return nil, err
	}
	found := map[string]adminapi.RouteInfo{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			// Local aliases such as `h := r.app.Admin.Handle`.
			alias := map[string]string{}
			ast.Inspect(f, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != len(as.Rhs) {
					return true
				}
				for i, rhs := range as.Rhs {
					id, ok1 := as.Lhs[i].(*ast.Ident)
					sel, ok2 := rhs.(*ast.SelectorExpr)
					if ok1 && ok2 && isRegister(sel.Sel.Name) {
						alias[id.Name] = sel.Sel.Name
					}
				}
				return true
			})
			var inner error
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || inner != nil || len(call.Args) == 0 {
					return true
				}
				kind := ""
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					kind = fn.Sel.Name
				case *ast.Ident:
					kind = alias[fn.Name]
				}
				if !isRegister(kind) {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				pattern, err := strconv.Unquote(lit.Value)
				if err != nil || !routeLiteral.MatchString(pattern) {
					return true
				}
				var extra []string
				if kind == "HandleRoles" {
					for _, a := range call.Args[2:] {
						name := ""
						switch x := a.(type) {
						case *ast.SelectorExpr:
							name = x.Sel.Name
						case *ast.Ident:
							name = x.Name
						}
						v, ok := roleNames[name]
						if !ok {
							inner = fmt.Errorf("%s: %s: role argument %q is not an adminapi Role constant", path, pattern, name)
							return false
						}
						extra = append(extra, v)
					}
				}
				ri := adminapi.DescribeRoute(pattern, extra, kind == "HandlePublic")
				if prev, dup := found[pattern]; dup && !sameRoute(prev, ri) {
					inner = fmt.Errorf("%s: %s is registered twice with different roles", path, pattern)
					return false
				}
				found[pattern] = ri
				return true
			})
			return inner
		})
		if err != nil {
			return nil, err
		}
	}
	const self = "GET /api/v1/openapi.json"
	if _, ok := found[self]; !ok {
		found[self] = adminapi.DescribeRoute(self, nil, false)
	}
	if len(found) == 0 {
		return nil, errors.New("no route registrations found; is -root the repository root?")
	}
	out := make([]adminapi.RouteInfo, 0, len(found))
	for _, r := range found {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pattern < out[j].Pattern })
	return out, nil
}

func isRegister(name string) bool {
	return name == "Handle" || name == "HandleRoles" || name == "HandlePublic"
}

func sameRoute(a, b adminapi.RouteInfo) bool {
	return a.Public == b.Public && a.Refined == b.Refined && strings.Join(a.Roles, ",") == strings.Join(b.Roles, ",")
}

// roleConstants maps the names of adminapi's Role* string constants to
// their values.
func roleConstants(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if !strings.HasPrefix(n.Name, "Role") || i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil {
							out[n.Name] = v
						}
					}
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no Role constants", dir)
	}
	return out, nil
}
