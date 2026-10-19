package graph

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func embeddedMap(t *testing.T) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	err := fs.WalkDir(embedded, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := fs.ReadFile(embedded, p)
		m[p] = &fstest.MapFile{Data: raw}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCatalogOneTemplatePerOperation(t *testing.T) {
	// FR-9.3: the catalog is the only way to reach the database. Op has
	// unexported fields, so code outside the catalog cannot build one with
	// its own text, and Backend takes only Ops. Each ID maps to exactly
	// one template, and every template is a fixed string from the
	// embedded file (no query is assembled at run time).
	reqtest.Verifies(t, "FR-9.3")
	c := DefaultCatalog()
	texts := map[string]string{}
	for _, id := range c.Ops() {
		op, err := c.Op(id)
		if err != nil {
			t.Fatal(err)
		}
		if op.ID() != id || op.Text() == "" || (op.Mode() != ModeRead && op.Mode() != ModeWrite) {
			t.Fatalf("op %s: %+v", id, op)
		}
		if prev, dup := texts[op.Text()]; dup && !strings.HasPrefix(id, "migration.") {
			t.Fatalf("ops %s and %s share a template", prev, id)
		}
		texts[op.Text()] = id
		raw, _ := fs.ReadFile(embedded, "templates/templates.cypher")
		mig := false
		for _, m := range c.Migrations() {
			for _, mo := range m.Ops {
				mig = mig || mo == op
			}
		}
		if !mig && !strings.Contains(string(raw), op.Text()) {
			t.Fatalf("op %s text is not verbatim from the template file", id)
		}
	}
	if _, err := c.Op("MATCH (n) DETACH DELETE n"); !errors.Is(err, ErrUnknownOp) {
		t.Fatalf("query text accepted as an op ID: %v", err)
	}
	das := NewDAS(NewFake(), c, nil)
	if _, err := das.read(context.Background(), "upsert.Session", map[string]any{"rows": []map[string]any{{"id": "x"}}}); !errors.Is(err, ErrUnknownOp) {
		t.Fatalf("write op run as a read: %v", err)
	}
	if c.SchemaVersion() != 2 || TemplateSetVersion == "" || len(c.Digest()) != 64 {
		t.Fatalf("version %d digest %q", c.SchemaVersion(), c.Digest())
	}
}

func TestTemplateDigestRefusesModifiedSet(t *testing.T) {
	// SR-1.13-2: the template set is verified against MANIFEST.sha256 at
	// load, and a changed, added or missing file is refused. The manifest
	// is the release's: it is embedded in the release binary beside the
	// templates, and the binary is covered by the signed release checksums.
	reqtest.Verifies(t, "SR-1.13-2")
	if _, err := LoadCatalog(embeddedMap(t)); err != nil {
		t.Fatal(err)
	}
	m := embeddedMap(t)
	m["templates/templates.cypher"].Data = []byte(strings.Replace(string(m["templates/templates.cypher"].Data), "LIMIT $limit", "", 1))
	if _, err := LoadCatalog(m); !errors.Is(err, ErrTemplateDigest) {
		t.Fatalf("modified template accepted: %v", err)
	}
	m = embeddedMap(t)
	m["templates/0003_extra.cypher"] = &fstest.MapFile{Data: []byte("CREATE INDEX x IF NOT EXISTS FOR (n:X) ON (n.y);")}
	if _, err := LoadCatalog(m); !errors.Is(err, ErrTemplateDigest) {
		t.Fatalf("unlisted file accepted: %v", err)
	}
	m = embeddedMap(t)
	delete(m, "templates/MANIFEST.sha256")
	if _, err := LoadCatalog(m); !errors.Is(err, ErrTemplateDigest) {
		t.Fatalf("missing manifest accepted: %v", err)
	}
	// A mirror built on a refused catalog never starts: New takes only a
	// loaded *Catalog, and the embedded one panics at init on mismatch.
}

func TestParametersAreValidatedAndNeverQueryText(t *testing.T) {
	// SR-1.13-1, unit part: undeclared parameters, wrong types, control
	// characters, oversize values, labels outside the fixed set and
	// unknown canned queries are refused before any statement runs. The
	// integration test proves that injected text in a bound value is not
	// executed by Neo4j.
	reqtest.Partial(t, "SR-1.13-1")
	f := NewFake()
	das := NewDAS(f, nil, nil)
	ctx := context.Background()
	op, _ := DefaultCatalog().Op("neighborhood.Session")
	for _, p := range []map[string]any{
		{"id": "s", "limit": int64(5), "query": "MATCH (n) RETURN n"},
		{"id": "s"},
		{"id": 5, "limit": int64(5)},
		{"id": "s\n}) DETACH DELETE n //", "limit": int64(5)},
		{"id": strings.Repeat("a", MaxStringParam+1), "limit": int64(5)},
		{"id": "s", "limit": int64(0)},
	} {
		if err := op.Validate(p); !errors.Is(err, ErrBadParameter) {
			t.Fatalf("%v accepted: %v", p, err)
		}
	}
	for _, label := range []string{"Session) DETACH DELETE (n", "Checkpoint", "", "session"} {
		if _, err := das.Neighborhood(ctx, label, "s", 5); !errors.Is(err, ErrBadParameter) {
			t.Fatalf("label %q: %v", label, err)
		}
	}
	if _, err := das.Query(ctx, "CALL dbms.killQueries", nil, 5); !errors.Is(err, ErrUnknownOp) {
		t.Fatal(err)
	}
	if _, err := das.Query(ctx, "call_timeline", map[string]string{"correlationId": "x' OR 1=1 //"}, 5); !errors.Is(err, ErrBadParameter) {
		t.Fatal(err)
	}
	if _, err := das.Query(ctx, "call_timeline", nil, 5); !errors.Is(err, ErrBadParameter) {
		t.Fatal("missing parameter accepted")
	}
	if _, err := das.Query(ctx, "recent_sessions", map[string]string{"label": "Session"}, 5); !errors.Is(err, ErrBadParameter) {
		t.Fatal("undeclared parameter accepted")
	}
	if f.reads != 0 {
		t.Fatalf("%d statements ran", f.reads)
	}
	// A projection node with a property outside the label allowlist is
	// refused (Community Edition has no property constraints).
	if err := validRow(nodeRow{label: "Session", id: "s", props: map[string]any{"password": "x"}}); !errors.Is(err, ErrBadParameter) {
		t.Fatal(err)
	}
	if err := validRow(nodeRow{label: "Checkpoint", id: "s"}); !errors.Is(err, ErrBadParameter) {
		t.Fatal(err)
	}
}

func TestTransactionFunctionsHoldOnlyDatabaseWork(t *testing.T) {
	// SR-7.1-1: the functions passed to ExecuteWrite and ExecuteRead, and
	// runTx which they call, call only transaction and result methods and
	// local value conversion. The check covers backend.go, the only file
	// that opens transactions; it is a source inspection, not a proof
	// over every future change.
	reqtest.Partial(t, "SR-7.1-1")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "backend.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"Run": true, "Collect": true, "AsMap": true, "runTx": true, "driverParams": true, "make": true, "len": true}
	check := func(n ast.Node, where string) {
		ast.Inspect(n, func(x ast.Node) bool {
			call, ok := x.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if !allowed[name] {
				t.Errorf("%s calls %s inside a retryable transaction function", where, name)
			}
			return true
		})
	}
	found := 0
	ast.Inspect(file, func(x ast.Node) bool {
		switch n := x.(type) {
		case *ast.FuncDecl:
			if n.Name.Name == "runTx" {
				check(n.Body, "runTx")
				found++
			}
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "ExecuteWrite" || sel.Sel.Name == "ExecuteRead") {
				for _, a := range n.Args {
					if fl, ok := a.(*ast.FuncLit); ok {
						check(fl.Body, sel.Sel.Name)
						found++
					}
				}
			}
		}
		return true
	})
	if found != 3 {
		t.Fatalf("found %d transaction functions, want 3", found)
	}
}
