package packaging_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
	"github.com/ethan03805/secure-mcp-gateway/internal/packaging/pkgtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

var refserver string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pkgtest-bin-")
	if err != nil {
		panic(err)
	}
	refserver = filepath.Join(dir, "smcp-refserver")
	cmd := exec.Command("go", "build", "-o", refserver, "github.com/ethan03805/secure-mcp-gateway/cmd/smcp-refserver")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic("build smcp-refserver: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func reason(err error) string { return packaging.ReasonOf(err) }

func TestEmbeddedSchemaMatchesPublished(t *testing.T) {
	reqtest.Partial(t, "FR-14.11")
	pub, err := os.ReadFile("../../docs/schemas/manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, packaging.ManifestSchemaJSON()) {
		t.Fatal("internal/packaging/manifest.schema.json differs from docs/schemas/manifest.schema.json; copy the published schema")
	}
}

// fixtureManifest returns a valid manifest as a generic JSON document.
func fixtureManifest(t *testing.T) map[string]any {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "p")
	pkgtest.Build(t, dir, pkgtest.Spec{ID: "m", Revision: "1"})
	raw, _ := os.ReadFile(filepath.Join(dir, packaging.ManifestFile))
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func parse(t *testing.T, m map[string]any) error {
	t.Helper()
	raw, _ := json.Marshal(m)
	_, err := packaging.ParseManifest(raw)
	return err
}

func TestManifestSchemaValidation(t *testing.T) {
	reqtest.Verifies(t, "FR-14.11")
	if err := parse(t, fixtureManifest(t)); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	for _, field := range []string{"manifest_version", "server", "artifact", "launch", "era", "risk_class", "instance_scope", "tools", "capabilities", "provenance", "packaging"} {
		m := fixtureManifest(t)
		delete(m, field)
		if err := parse(t, m); reason(err) != packaging.ReasonManifestSchema {
			t.Errorf("without %s: %v", field, err)
		}
	}
	// Field rules inside required members.
	for name, edit := range map[string]func(m map[string]any){
		"bad server id":      func(m map[string]any) { m["server"].(map[string]any)["id"] = "Bad ID" },
		"latest version":     func(m map[string]any) { m["artifact"].(map[string]any)["version"] = "latest" },
		"short digest":       func(m map[string]any) { m["artifact"].(map[string]any)["sha256"] = "abc" },
		"unknown era":        func(m map[string]any) { m["era"] = "2024-11-05" },
		"unknown risk":       func(m map[string]any) { m["risk_class"] = "none" },
		"empty tools":        func(m map[string]any) { m["tools"] = []any{} },
		"unknown member":     func(m map[string]any) { m["extra"] = true },
		"description digest": func(m map[string]any) { m["tools"].([]any)[0].(map[string]any)["description"] = "changed" },
		"tools_list_sha256":  func(m map[string]any) { m["tools_list_sha256"] = strings.Repeat("0", 64) },
		"side effect":        func(m map[string]any) { m["tools"].([]any)[0].(map[string]any)["side_effect"] = "maybe" },
		"undeclared slot":    func(m map[string]any) { m["launch"].(map[string]any)["argv"] = []any{"server", "{root}"} },
		"runtime/type":       func(m map[string]any) { m["launch"].(map[string]any)["runtime"] = "node" },
		"lower per-tool class": func(m map[string]any) {
			m["risk_class"] = "moderate"
			m["tools"].([]any)[0].(map[string]any)["risk_class"] = "low"
		},
	} {
		m := fixtureManifest(t)
		edit(m)
		if err := parse(t, m); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	m := fixtureManifest(t)
	m["manifest_version"] = 2
	if err := parse(t, m); reason(err) != packaging.ReasonManifestVersion || !strings.Contains(err.Error(), "2") {
		t.Errorf("version 2: %v", err)
	}
}

func TestLaunchVectorRules(t *testing.T) {
	reqtest.Verifies(t, "FR-14.4")
	reqtest.Partial(t, "SR-3.6-1")
	for _, argv := range [][]any{{"npx", "-y", "@modelcontextprotocol/server-filesystem"}, {"uvx", "mcp-server-fetch"}, {"/usr/bin/pip", "install", "x"}, {"bash", "-c", "x"}} {
		m := fixtureManifest(t)
		m["launch"].(map[string]any)["argv"] = argv
		if err := parse(t, m); err == nil {
			t.Errorf("argv %v accepted", argv)
		}
	}
	m := fixtureManifest(t)
	m["launch"].(map[string]any)["runtime"] = "python"
	m["artifact"].(map[string]any)["type"] = "pypi"
	m["launch"].(map[string]any)["argv"] = []any{"python3", "-m", "pip", "install", "x"}
	if err := parse(t, m); reason(err) != packaging.ReasonUnpinnedLaunch {
		t.Errorf("python -m pip: %v", err)
	}
	for _, u := range []string{"https://mcp.example.com/mcp", "wss://mcp.example.com"} {
		m := fixtureManifest(t)
		m["launch"].(map[string]any)["argv"] = []any{u}
		if err := parse(t, m); reason(err) != packaging.ReasonRemoteBackend {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestPinnedReferencesOnly(t *testing.T) {
	reqtest.Verifies(t, "FR-14.2")
	sha := strings.Repeat("a", 64)
	integ := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))
	bad := map[string]packaging.ArtifactRef{
		"caret range":         {Type: "npm", Name: "x", Version: "^1.2.3", Integrity: integ},
		"tilde range":         {Type: "npm", Name: "x", Version: "~1.2", Integrity: integ},
		"x range":             {Type: "npm", Name: "x", Version: "1.x", Integrity: integ},
		"comparison range":    {Type: "pypi", Name: "x", Version: ">=1.0", SHA256: sha},
		"star":                {Type: "npm", Name: "x", Version: "*", Integrity: integ},
		"latest tag":          {Type: "npm", Name: "x", Version: "latest", Integrity: integ},
		"next tag":            {Type: "npm", Name: "x", Version: "next", Integrity: integ},
		"no version":          {Type: "pypi", Name: "x", SHA256: sha},
		"OCI tag only":        {Type: "oci", Name: "docker.io/mcp/fetch", Version: "latest"},
		"OCI tag no digest":   {Type: "oci", Name: "docker.io/mcp/fetch", Version: "1.0.0"},
		"npm without digest":  {Type: "npm", Name: "x", Version: "1.0.0"},
		"pypi without digest": {Type: "pypi", Name: "x", Version: "1.0.0"},
		"binary no digest":    {Type: "binary", Name: "/bin/true", Version: "1"},
		"binary over http":    {Type: "binary", Name: "http://example.com/x", Version: "1", SHA256: sha},
	}
	for name, ref := range bad {
		r := &packaging.Recipe{RecipeVersion: 1, Artifact: ref, Server: packaging.ServerInfo{ID: "x", Alias: "x", Publisher: "p"},
			Launch: packaging.Launch{Runtime: "native", Argv: []string{"x"}}}
		_, err := packaging.Build(context.Background(), r, filepath.Join(t.TempDir(), "out"), packaging.BuildOptions{})
		if reason(err) != packaging.ReasonUnpinned {
			t.Errorf("%s: %v", name, err)
		} else if !strings.Contains(err.Error(), ref.Name) && !strings.Contains(err.Error(), "version") && !strings.Contains(err.Error(), "digest") && !strings.Contains(err.Error(), "https") {
			t.Errorf("%s: reason not named: %v", name, err)
		}
	}
	for _, ok := range []packaging.ArtifactRef{
		{Type: "npm", Name: "@modelcontextprotocol/server-memory", Version: "2026.8.31", Integrity: integ},
		{Type: "pypi", Name: "x", Version: "2026.8.18", SHA256: sha},
		{Type: "oci", Name: "docker.io/mcp/fetch", Version: "1.0.0", Integrity: "sha256:" + sha},
		{Type: "binary", Name: "/bin/true", Version: "1.0.0-rc.1", SHA256: sha},
	} {
		if err := ok.Check(); err != nil {
			t.Errorf("%+v refused: %v", ok, err)
		}
	}
}

func refRecipe(t *testing.T) *packaging.Recipe {
	t.Helper()
	sum, _, err := packaging.FileSHA256(refserver)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src.tar.gz")
	os.WriteFile(src, []byte("source archive"), 0o644)
	return &packaging.Recipe{RecipeVersion: 1,
		Server:        packaging.ServerInfo{ID: "ref", Alias: "ref", Publisher: "test"},
		Artifact:      packaging.ArtifactRef{Type: "binary", Name: refserver, Version: "1.0.0", SHA256: sum},
		Launch:        packaging.Launch{Runtime: "native", Argv: []string{"smcp-refserver", "--root", "{root}"}},
		RiskClass:     "low",
		InstanceScope: []string{"shared"},
		Tools: packaging.RecipeTools{Default: packaging.ToolClass{SideEffect: "read", SourceTrust: "trusted"},
			Overrides: map[string]packaging.ToolClass{"read_file": {SourceTrust: "untrusted"}}, Expect: []string{"read_file"}},
		Capabilities: packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{{Slot: "root", Mode: "ro", ArgvPlaceholder: "{root}"}}},
		Source:       &packaging.RecipeSource{Kind: "archive", URI: "https://example.invalid/src.tar.gz", Path: src},
		Licenses:     []string{"Apache-2.0"},
	}
}

func TestBuildSignVerifyBinary(t *testing.T) {
	reqtest.Partial(t, "FR-14.1", "FR-14.3", "FR-14.5", "FR-14.6", "FR-14.7", "SR-3.5-1")
	r := refRecipe(t)
	out := filepath.Join(t.TempDir(), "pkg")
	pkg, err := packaging.Build(context.Background(), r, out, packaging.BuildOptions{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	// The artifact is stored under its SHA-256, which the manifest, index
	// and provenance statement all name.
	sum, _, _ := packaging.FileSHA256(filepath.Join(out, "artifact", "smcp-refserver"))
	if sum != r.Artifact.SHA256 || pkg.Index.Artifact.SHA256 != sum || pkg.Manifest.Artifact.SHA256 != sum || pkg.Provenance.Artifact.SHA256 != sum {
		t.Fatal("artifact digest bindings")
	}
	// FR-14.5: source reference and licenses bound to the artifact digest.
	if pkg.Provenance.Source.URI != r.Source.URI || pkg.Provenance.Source.SHA256 != packaging.SHA256Hex([]byte("source archive")) || pkg.Provenance.Licenses[0] != "Apache-2.0" {
		t.Fatalf("provenance: %+v", pkg.Provenance)
	}
	// SR-3.5-1 (Standalone): the probe saw only PATH and HOME.
	if strings.Join(pkg.Provenance.Probe.EnvNames, ",") != "HOME,PATH" || pkg.Provenance.Probe.Network != "host" {
		t.Fatalf("probe environment: %+v", pkg.Provenance.Probe)
	}
	// FR-14.3: the manifest validates and its tools equal the live list.
	raw, _ := os.ReadFile(filepath.Join(out, packaging.ManifestFile))
	m, err := packaging.ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	tree := t.TempDir()
	packaging.CopyFile(refserver, filepath.Join(tree, "smcp-refserver"), 0o755)
	spec, err := packaging.ResolveLaunch(packaging.LaunchInput{Manifest: m, Root: tree, Slots: map[string]string{"root": root}, WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	live, err := packaging.Probe(context.Background(), spec, packaging.ProbeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lc, _ := packaging.CanonicalLive(live.Tools)
	if d := packaging.Drift(m.CanonicalTools(), lc); len(d) != 0 || len(m.Tools) != 4 {
		t.Fatalf("manifest tools differ from the live list: %v", d)
	}
	if m.Find("read_file").SourceTrust != "untrusted" || m.Find("echo").SourceTrust != "trusted" || m.Era != "2025-11-25" {
		t.Fatal("classification or era")
	}

	// FR-14.6 and FR-14.7: sign with a key file; verify; tamper.
	key := pkgtest.NewKey(t)
	if err := packaging.Sign(out, key.Private, time.Now()); err != nil {
		t.Fatal(err)
	}
	pub, _ := packaging.ParsePublicKey(key.Public)
	if _, err := packaging.Verify(out, packaging.VerifyOptions{Keys: packaging.PublicKeyResolver(pub)}); err != nil {
		t.Fatalf("intact package: %v", err)
	}
	other := pkgtest.NewKey(t)
	opub, _ := packaging.ParsePublicKey(other.Public)
	if _, err := packaging.Verify(out, packaging.VerifyOptions{Keys: packaging.PublicKeyResolver(opub)}); reason(err) != packaging.ReasonSignerUnknown {
		t.Fatalf("wrong key: %v", err)
	}
	for _, f := range []string{packaging.ManifestFile, "artifact/smcp-refserver"} {
		cp := filepath.Join(t.TempDir(), "copy")
		if err := packaging.CopyPackage(out, cp); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(cp, filepath.FromSlash(f))
		b, _ := os.ReadFile(p)
		os.WriteFile(p, append(b, ' '), 0o644)
		if _, err := packaging.Verify(cp, packaging.VerifyOptions{Keys: packaging.PublicKeyResolver(pub)}); reason(err) != packaging.ReasonDigestMismatch {
			t.Fatalf("modified %s: %v", f, err)
		}
	}
	// An unexpected tool override is refused (classification mistake).
	r2 := refRecipe(t)
	r2.Tools.Overrides = map[string]packaging.ToolClass{"no_such_tool": {SideEffect: "write"}}
	if _, err := packaging.Build(context.Background(), r2, filepath.Join(t.TempDir(), "o"), packaging.BuildOptions{}); err == nil {
		t.Fatal("override of an unknown tool accepted")
	}
	// A wrong pinned digest is refused before anything runs.
	r3 := refRecipe(t)
	r3.Artifact.SHA256 = strings.Repeat("b", 64)
	if _, err := packaging.Build(context.Background(), r3, filepath.Join(t.TempDir(), "o"), packaging.BuildOptions{}); reason(err) != packaging.ReasonDigestMismatch {
		t.Fatalf("wrong digest: %v", err)
	}
}

func TestEncryptedSigningKey(t *testing.T) {
	reqtest.Partial(t, "FR-14.6") // the interactive prompt is exercised by hand only
	key := pkgtest.NewKey(t)
	// Low scrypt cost for the test; GenerateKey uses minisign's 1 GiB cost.
	sec, err := packaging.EncryptSecretKeyCost("correct horse battery", key.Private, 1<<15, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw := key.Public
	if !packaging.SecretKeyEncrypted(sec) {
		t.Fatal("key not encrypted")
	}
	if _, err := packaging.ParseSecretKey(sec, "wrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	k, err := packaging.ParseSecretKey(sec, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "p")
	pkgtest.Build(t, dir, pkgtest.Spec{ID: "enc", Revision: "1"})
	if err := packaging.Sign(dir, k, time.Now()); err != nil {
		t.Fatal(err)
	}
	pub, _ := packaging.ParsePublicKey(pubRaw)
	if _, err := packaging.Verify(dir, packaging.VerifyOptions{Keys: packaging.PublicKeyResolver(pub)}); err != nil {
		t.Fatal(err)
	}
}

// --- registry fixtures -----------------------------------------------------

func tgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		tw.Write([]byte(files[n]))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func sha512Integrity(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

// jsServer is a dependency-free MCP stdio server (initialize, tools/list).
const jsServer = `const rl = require('readline').createInterface({input: process.stdin});
const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");
rl.on('line', (l) => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'initialize') return send({jsonrpc: '2.0', id: m.id, result: {protocolVersion: '2025-11-25', capabilities: {tools: {}}, serverInfo: {name: 'js', version: '1'}}});
  if (m.method === 'tools/list') return send({jsonrpc: '2.0', id: m.id, result: {tools: [{name: 'hello', description: 'Say hello.', inputSchema: {type: 'object'}}]}});
  send({jsonrpc: '2.0', id: m.id, error: {code: -32601, message: 'method not found'}});
});
`

const pyServer = `import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if "id" not in m:
        continue
    if m.get("method") == "initialize":
        r = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "py", "version": "1"}}
        out = {"jsonrpc": "2.0", "id": m["id"], "result": r}
    elif m.get("method") == "tools/list":
        out = {"jsonrpc": "2.0", "id": m["id"], "result": {"tools": [{"name": "add", "description": "Add numbers.", "inputSchema": {"type": "object"}}]}}
    else:
        out = {"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "method not found"}}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
`

func wheel(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"fixture_mcp/__init__.py": "", "fixture_mcp/__main__.py": pyServer,
		"fixture_mcp-1.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: fixture-mcp\nVersion: 1.0.0\n"} {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

type registries struct {
	srv       *httptest.Server
	npmTGZ    []byte
	whl       []byte
	sdistSHA  string
	ociDigest string
	layer     []byte
}

func newRegistries(t *testing.T) *registries {
	t.Helper()
	return newRegistriesImage(t, tgz(t, map[string]string{"app/server": "binary"}), nil)
}

// newRegistriesImage is newRegistries with the OCI image's one gzip layer
// and its diff_ids (needed when the image is run, not only fetched).
func newRegistriesImage(t *testing.T, layer []byte, diffIDs []string) *registries {
	t.Helper()
	r := &registries{npmTGZ: tgz(t, map[string]string{"package/package.json": `{"name":"@fx/hello","version":"1.2.3"}`, "package/index.js": jsServer}), whl: wheel(t)}
	r.sdistSHA = packaging.SHA256Hex([]byte("sdist"))
	// OCI: an index pointing at a linux image for this architecture.
	r.layer = layer
	ids := []byte("[]")
	if diffIDs != nil {
		ids, _ = json.Marshal(diffIDs)
	}
	cfg := []byte(`{"architecture":"` + runtime.GOARCH + `","os":"linux","config":{"Labels":{"org.opencontainers.image.source":"https://example.invalid/src"}},"rootfs":{"type":"layers","diff_ids":` + string(ids) + `}}`)
	img, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + packaging.SHA256Hex(cfg), "size": len(cfg)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + packaging.SHA256Hex(r.layer), "size": len(r.layer)}}})
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + packaging.SHA256Hex(img), "size": len(img),
			"platform": map[string]any{"os": "linux", "architecture": runtime.GOARCH}}}})
	r.ociDigest = "sha256:" + packaging.SHA256Hex(idx)
	blobs := map[string][]byte{"sha256:" + packaging.SHA256Hex(cfg): cfg, "sha256:" + packaging.SHA256Hex(r.layer): r.layer}
	manifests := map[string][]byte{r.ociDigest: idx, "sha256:" + packaging.SHA256Hex(img): img}
	mux := http.NewServeMux()
	mux.HandleFunc("/npm/@fx/hello/-/hello-1.2.3.tgz", func(w http.ResponseWriter, _ *http.Request) { w.Write(r.npmTGZ) })
	mux.HandleFunc("/pypi/pypi/fixture-mcp/1.0.0/json", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"urls": []any{
			map[string]any{"filename": "fixture_mcp-1.0.0-py3-none-any.whl", "url": r.srv.URL + "/files/fixture_mcp-1.0.0-py3-none-any.whl", "packagetype": "bdist_wheel", "digests": map[string]string{"sha256": packaging.SHA256Hex(r.whl)}},
			map[string]any{"filename": "fixture_mcp-1.0.0.tar.gz", "url": r.srv.URL + "/files/fixture_mcp-1.0.0.tar.gz", "packagetype": "sdist", "digests": map[string]string{"sha256": r.sdistSHA}},
		}})
	})
	mux.HandleFunc("/files/fixture_mcp-1.0.0-py3-none-any.whl", func(w http.ResponseWriter, _ *http.Request) { w.Write(r.whl) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("scope") != "repository:fx/img:pull" {
			http.Error(w, "scope", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
	})
	mux.HandleFunc("/v2/fx/img/", func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer tok" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="test"`, r.srv.URL))
			w.WriteHeader(401)
			return
		}
		parts := strings.Split(req.URL.Path, "/")
		d := parts[len(parts)-1]
		if strings.Contains(req.URL.Path, "/manifests/") {
			if b, ok := manifests[d]; ok {
				w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
				w.Write(b)
				return
			}
		} else if b, ok := blobs[d]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, req)
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *registries) fetcher() *packaging.Fetcher {
	return &packaging.Fetcher{NPMRegistry: r.srv.URL + "/npm", PyPIIndex: r.srv.URL + "/pypi", OCIPlainHTTP: true}
}

func TestFetchEachArtifactType(t *testing.T) {
	reqtest.Partial(t, "FR-14.1") // OCI images are fetched here but not probed (needs podman)
	r := newRegistries(t)
	f := r.fetcher()
	host := strings.TrimPrefix(r.srv.URL, "http://")
	binSHA, _, _ := packaging.FileSHA256(refserver)
	ok := map[string]packaging.ArtifactRef{
		"npm":    {Type: "npm", Name: "@fx/hello", Version: "1.2.3", Integrity: sha512Integrity(r.npmTGZ)},
		"pypi":   {Type: "pypi", Name: "fixture-mcp", Version: "1.0.0", SHA256: packaging.SHA256Hex(r.whl)},
		"oci":    {Type: "oci", Name: host + "/fx/img", Version: "1.0.0", Integrity: r.ociDigest},
		"binary": {Type: "binary", Name: refserver, Version: "1.0.0", SHA256: binSHA},
	}
	for name, ref := range ok {
		fe, err := f.Fetch(context.Background(), ref, t.TempDir())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, _, _ := packaging.FileSHA256(fe.Path); got != fe.SHA256 {
			t.Fatalf("%s: reported digest", name)
		}
		switch name {
		case "npm":
			if fe.SourceKind != "registry-tarball" || fe.RegistryIntegrity != ref.Integrity {
				t.Errorf("npm source: %+v", fe)
			}
		case "pypi":
			if fe.SourceKind != "sdist" || fe.SourceSHA256 != r.sdistSHA {
				t.Errorf("pypi source: %+v", fe)
			}
		case "oci":
			if fe.SourceKind != "oci-source-label" || !strings.HasPrefix(fe.RegistryIntegrity, "sha256:") || fe.RegistryIntegrity == r.ociDigest {
				t.Errorf("oci: %+v", fe)
			}
			if !ociLayoutHas(t, fe.Path, "oci-layout", "index.json", "blobs/sha256/"+packaging.SHA256Hex(r.layer)) {
				t.Error("OCI layout incomplete")
			}
		}
	}
	wrong := map[string]packaging.ArtifactRef{
		"npm":    {Type: "npm", Name: "@fx/hello", Version: "1.2.3", Integrity: sha512Integrity([]byte("other"))},
		"pypi":   {Type: "pypi", Name: "fixture-mcp", Version: "1.0.0", SHA256: strings.Repeat("c", 64)},
		"oci":    {Type: "oci", Name: host + "/fx/img", Version: "1.0.0", Integrity: "sha256:" + strings.Repeat("d", 64)},
		"binary": {Type: "binary", Name: refserver, Version: "1.0.0", SHA256: strings.Repeat("e", 64)},
	}
	for name, ref := range wrong {
		_, err := f.Fetch(context.Background(), ref, t.TempDir())
		if err == nil {
			t.Errorf("%s: wrong digest accepted", name)
		} else if name != "oci" && reason(err) != packaging.ReasonDigestMismatch {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func ociLayoutHas(t *testing.T, path string, names ...string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	seen := map[string]bool{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		seen[h.Name] = true
	}
	for _, n := range names {
		if !seen[n] {
			return false
		}
	}
	return true
}

func TestBuildNPMAndPyPI(t *testing.T) {
	reqtest.Partial(t, "FR-14.1", "FR-14.3")
	r := newRegistries(t)
	cases := []struct {
		name, tool string
		need       string
		recipe     packaging.Recipe
	}{
		{"npm", "hello", "node", packaging.Recipe{
			Artifact: packaging.ArtifactRef{Type: "npm", Name: "@fx/hello", Version: "1.2.3", Integrity: sha512Integrity(r.npmTGZ)},
			Launch:   packaging.Launch{Runtime: "node", Argv: []string{"node", "node_modules/@fx/hello/index.js"}}}},
		{"pypi", "add", "python3", packaging.Recipe{
			Artifact: packaging.ArtifactRef{Type: "pypi", Name: "fixture-mcp", Version: "1.0.0", SHA256: packaging.SHA256Hex(r.whl)},
			Launch:   packaging.Launch{Runtime: "python", Argv: []string{"python3", "-m", "fixture_mcp"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := exec.LookPath(c.need); err != nil {
				t.Skipf("%s not installed", c.need)
			}
			rc := c.recipe
			rc.RecipeVersion = 1
			rc.Server = packaging.ServerInfo{ID: "fx-" + c.name, Alias: c.name, Publisher: "test"}
			rc.RiskClass, rc.InstanceScope, rc.Licenses = "low", []string{"shared"}, []string{"MIT"}
			rc.Tools = packaging.RecipeTools{Default: packaging.ToolClass{SideEffect: "read", SourceTrust: "trusted"}}
			out := filepath.Join(t.TempDir(), "pkg")
			pkg, err := packaging.Build(context.Background(), &rc, out, packaging.BuildOptions{Fetcher: r.fetcher()})
			if err != nil {
				t.Fatal(err)
			}
			if len(pkg.Manifest.Tools) != 1 || pkg.Manifest.Tools[0].Name != c.tool || pkg.Manifest.Era != "2025-11-25" {
				t.Fatalf("manifest: %+v", pkg.Manifest.Tools)
			}
			art := filepath.Join(out, filepath.FromSlash(pkg.Index.Artifact.Path))
			if sum, _, _ := packaging.FileSHA256(art); sum != pkg.Index.Artifact.SHA256 || !strings.HasSuffix(art, ".tar.gz") {
				t.Fatalf("artifact %s", art)
			}
			// The assembled artifact is deterministic.
			out2 := filepath.Join(t.TempDir(), "pkg")
			pkg2, err := packaging.Build(context.Background(), &rc, out2, packaging.BuildOptions{Fetcher: r.fetcher()})
			if err != nil || pkg2.Index.Artifact.SHA256 != pkg.Index.Artifact.SHA256 {
				t.Fatalf("rebuild digest differs: %v", err)
			}
		})
	}
}

func TestResolveLaunch(t *testing.T) {
	m := &packaging.Manifest{Artifact: packaging.ArtifactInfo{Type: "oci"}, Launch: packaging.Launch{Runtime: "oci", Argv: []string{"/app/server", "{data}"},
		EnvFixed: map[string]string{"STORE": "{data}/store.json"}},
		Capabilities: packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{{Slot: "data", Mode: "rw", ArgvPlaceholder: "{data}"}}}}
	data := t.TempDir()
	spec, err := packaging.ResolveLaunch(packaging.LaunchInput{Manifest: m, Alias: "x", Archive: "/state/a.tar", Slots: map[string]string{"data": data}, Interp: packaging.Interpreters{Podman: "/usr/bin/podman"}})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(spec.Args, " ")
	for _, want := range []string{"--network=none", "--read-only", "-v " + data + ":/slots/data:rw", "-e STORE=/slots/data/store.json", "oci-archive:/state/a.tar /app/server /slots/data"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q lack %q", args, want)
		}
	}
	if err := pipeline.CheckLaunchSpec(spec); err != nil {
		t.Errorf("podman oci-archive refused: %v", err)
	}
	// The launch specification carries the manifest's runtime and declared
	// slots for the sandbox (SR-4.6-1); an OCI package has no artifact tree.
	if spec.Runtime != "oci" || spec.ArtifactRoot != "" || len(spec.Roots) != 1 || spec.Roots[0] != (pipeline.Root{Slot: "data", Path: data, Write: true}) {
		t.Errorf("runtime %q tree %q roots %v", spec.Runtime, spec.ArtifactRoot, spec.Roots)
	}
	node := &packaging.Manifest{Artifact: packaging.ArtifactInfo{Type: "npm"}, Launch: packaging.Launch{Runtime: "node", Argv: []string{"node", "dist/index.js"}}}
	tree := t.TempDir()
	if spec, err := packaging.ResolveLaunch(packaging.LaunchInput{Manifest: node, Alias: "n", Root: tree, Interp: packaging.Interpreters{Node: "/usr/bin/node"}}); err != nil ||
		spec.Runtime != "node" || spec.ArtifactRoot != tree || spec.Roots == nil || len(spec.Roots) != 0 {
		t.Errorf("node: %v runtime %q tree %q roots %#v", err, spec.Runtime, spec.ArtifactRoot, spec.Roots)
	}
	if _, err := packaging.ResolveLaunch(packaging.LaunchInput{Manifest: m, Interp: packaging.Interpreters{Podman: "/usr/bin/podman"}}); err == nil {
		t.Error("unbound slot accepted")
	}
	if _, err := packaging.ResolveLaunch(packaging.LaunchInput{Manifest: m, Slots: map[string]string{"data": data}, Env: map[string]string{"SECRET": "x"}, Interp: packaging.Interpreters{Podman: "/usr/bin/podman"}}); err == nil {
		t.Error("environment variable outside the allowlist accepted")
	}
}

func TestArchiveSafety(t *testing.T) {
	dir := t.TempDir()
	evil := filepath.Join(dir, "evil.tgz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	tw.Write([]byte("x"))
	tw.Close()
	gz.Close()
	os.WriteFile(evil, buf.Bytes(), 0o644)
	if err := packaging.ExtractTarGz(evil, filepath.Join(dir, "out"), ""); err == nil {
		t.Fatal("path traversal extracted")
	}
	buf.Reset()
	gz = gzip.NewWriter(&buf)
	tw = tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	tw.Close()
	gz.Close()
	os.WriteFile(evil, buf.Bytes(), 0o644)
	if err := packaging.ExtractTarGz(evil, filepath.Join(dir, "out2"), ""); err == nil {
		t.Fatal("symlink extracted")
	}
	// TreeDigest changes with content and with the executable bit.
	tree := t.TempDir()
	os.WriteFile(filepath.Join(tree, "f"), []byte("a"), 0o644)
	d1, _ := packaging.TreeDigest(tree)
	os.Chmod(filepath.Join(tree, "f"), 0o755)
	d2, _ := packaging.TreeDigest(tree)
	os.WriteFile(filepath.Join(tree, "f"), []byte("b"), 0o755)
	d3, _ := packaging.TreeDigest(tree)
	if d1 == d2 || d2 == d3 {
		t.Fatal("tree digest insensitive")
	}
	os.Symlink("/etc", filepath.Join(tree, "l"))
	if _, err := packaging.TreeDigest(tree); err == nil {
		t.Fatal("symlink in tree accepted")
	}
}
