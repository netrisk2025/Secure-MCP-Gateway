package openapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/adminapi"
	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var routeLiteral = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE) /(api|admin)/v1/[A-Za-z0-9_./{}-]*$`)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// registeredPatterns finds every control API route pattern in the Go
// sources: a string literal "METHOD /api/v1/..." or "METHOD /admin/v1/...".
// The role matrix and this package only refer to routes and are skipped.
func registeredPatterns(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	seen := map[string]bool{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "openapi" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, "rolematrix.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil && routeLiteral.MatchString(v) {
						seen[v] = true
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	seen["GET /api/v1/openapi.json"] = true // registered by this package
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func described() []string {
	out := make([]string, 0, len(ops))
	for _, o := range ops {
		out = append(out, o.Pattern)
	}
	sort.Strings(out)
	return out
}

// TestEveryRouteIsDescribed is FR-8.1: every route registered on the
// control API is described in the OpenAPI document, the document names no
// route that does not exist, every operation has a summary and a reference
// page, and every control API path the console uses maps to a described
// operation.
func TestEveryRouteIsDescribed(t *testing.T) {
	reqtest.Verifies(t, "FR-8.1")
	reg := registeredPatterns(t)
	desc := described()
	for _, p := range reg {
		if !slices.Contains(desc, p) {
			t.Errorf("route %q is registered but not described in internal/openapi/routes.go", p)
		}
	}
	for _, p := range desc {
		if !slices.Contains(reg, p) {
			t.Errorf("routes.go describes %q, which no package registers", p)
		}
	}
	dup := map[string]bool{}
	root := repoRoot(t)
	for _, o := range ops {
		if dup[o.Pattern] {
			t.Errorf("duplicate row %q", o.Pattern)
		}
		dup[o.Pattern] = true
		if o.Summary == "" || o.Tag == "" {
			t.Errorf("%q has no summary or tag", o.Pattern)
		}
		if _, err := os.Stat(filepath.Join(root, "docs", "api", o.Doc)); err != nil {
			t.Errorf("%q: reference page: %v", o.Pattern, err)
		}
	}
	// The role matrix names only real routes.
	for _, p := range adminapi.MatrixPatterns() {
		if !slices.Contains(reg, p) {
			t.Errorf("role matrix names %q, which no package registers", p)
		}
	}
	// Every control API path in the console sources is a described path.
	paths := map[string]bool{}
	for _, o := range ops {
		_, p, _ := strings.Cut(o.Pattern, " ")
		paths[p] = true
	}
	consolePath := regexp.MustCompile("[\"'`](/(?:api|admin)/v1/[^\"'`?#]*)")
	tmpl := regexp.MustCompile(`\$\{[^}]*\}`)
	consolePattern := regexp.MustCompile(`"((?:GET|POST|DELETE) /(?:api|admin)/v1/[^"]*)"`)
	queryTail := regexp.MustCompile(`([^/])\$\{.*$`)
	used := 0
	err := filepath.WalkDir(filepath.Join(root, "console", "src"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".tsx")) {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Route patterns the console checks permissions for ("POST /api/v1/backup").
		for _, m := range consolePattern.FindAllStringSubmatch(string(b), -1) {
			if !slices.Contains(desc, m[1]) {
				t.Errorf("%s checks the permission of %q, which is not a described route", filepath.Base(path), m[1])
			}
		}
		for _, m := range consolePath.FindAllStringSubmatch(string(b), -1) {
			// "/api/v1/x${query}": a query string built in code is cut off;
			// "/api/v1/x/${id}" is a path parameter.
			raw := queryTail.ReplaceAllString(m[1], "$1")
			p := strings.TrimSuffix(tmpl.ReplaceAllString(raw, "{x}"), "/")
			used++
			if !matchesAny(p, paths) {
				t.Errorf("%s uses %s, which is not a described path", filepath.Base(path), m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if used < 20 {
		t.Fatalf("found only %d control API paths in console/src", used)
	}
}

func matchesAny(p string, paths map[string]bool) bool {
	segs := strings.Split(p, "/")
	for d := range paths {
		ds := strings.Split(d, "/")
		if len(ds) != len(segs) {
			continue
		}
		ok := true
		for i := range ds {
			if segs[i] == "{x}" || strings.HasPrefix(ds[i], "{") || ds[i] == segs[i] {
				continue
			}
			ok = false
			break
		}
		if ok {
			return true
		}
	}
	return false
}

type nopCtl struct{}

func (nopCtl) Health() edge.Health                                   { return edge.Health{} }
func (nopCtl) Stop(string, string) error                             { return nil }
func (nopCtl) Resume(string) error                                   { return nil }
func (nopCtl) ActivatePolicy(string, *policy.Snapshot) (bool, error) { return false, nil }

func TestServedDocument(t *testing.T) {
	reqtest.Partial(t, "FR-8.1", "FR-8.2")
	dir := t.TempDir()
	if err := keys.Ensure(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("[admin_listener]\naddress = \"127.0.0.1:8444\"\n[state]\ndir = \"" + dir + "\"\n[admin]\nusername = \"admin\"\npassword_hash = \"$argon2id$x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := adminapi.New(adminapi.Options{Config: cfg, Controller: nopCtl{}, Evidence: &audit.Memory{}})
	if err != nil {
		t.Fatal(err)
	}
	Register(s)
	tok, _ := keys.LoadAdminToken(dir)
	req := httptest.NewRequest("GET", "/api/v1/openapi.json", nil)
	req.Host = "127.0.0.1:8444"
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var doc struct {
		OpenAPI string                               `json:"openapi"`
		Paths   map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" || len(doc.Paths) < 60 {
		t.Fatalf("document: %s, %d paths", doc.OpenAPI, len(doc.Paths))
	}
	stop := doc.Paths["/admin/v1/stop"]["post"]
	roles, _ := stop["x-smcp-roles"].([]any)
	if len(roles) != 2 || roles[0] != "administrator" || roles[1] != "operator" {
		t.Fatalf("stop roles: %v", stop["x-smcp-roles"])
	}
	if login := doc.Paths["/admin/v1/login"]["post"]; login["x-smcp-public"] != true {
		t.Fatalf("login: %v", login)
	}
	if p := doc.Paths["/api/v1/sessions/{id}"]["get"]; p["operationId"] != "getSessionsId" || len(p["parameters"].([]any)) != 1 {
		t.Fatalf("sessions/{id}: %v", p)
	}
	ids := map[string]bool{}
	for _, item := range doc.Paths {
		for _, o := range item {
			id := o["operationId"].(string)
			if ids[id] {
				t.Fatalf("duplicate operationId %s", id)
			}
			ids[id] = true
		}
	}
}
