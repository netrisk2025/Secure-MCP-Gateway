// Package pkgtest builds signed server packages for tests without running
// a probe: the manifest is assembled from given tool definitions, so tests
// of the verifier and registry need no network and no subprocess.
package pkgtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/packaging"
)

// Key is a test signing key.
type Key struct {
	Private minisign.PrivateKey
	Public  []byte // public key file contents
	ID      string
}

// NewKey generates an unencrypted key.
func NewKey(t testing.TB) Key {
	t.Helper()
	sec, pub, id, err := packaging.GenerateKey("")
	if err != nil {
		t.Fatal(err)
	}
	k, err := packaging.ParseSecretKey(sec, "")
	if err != nil {
		t.Fatal(err)
	}
	return Key{Private: k, Public: pub, ID: id}
}

// Spec describes a fixture package.
type Spec struct {
	ID, Revision, Alias string
	Risk                string
	Tools               []*mcp.Tool // default: one "echo" tool
	Artifact            []byte      // default: a small script body
	ArtifactName        string      // default "server"
	Argv                []string    // default [ArtifactName]
	Expires             string
	Stateful            bool
	// Edit changes the manifest and provenance before the index is written.
	Edit func(m *packaging.Manifest, p *packaging.Provenance)
}

// EchoTool is the default fixture tool.
func EchoTool(desc string) *mcp.Tool {
	return &mcp.Tool{Name: "echo", Description: desc, InputSchema: map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}}}
}

// Build writes an unsigned package for s into dir (which must not exist).
func Build(t testing.TB, dir string, s Spec) {
	t.Helper()
	if s.Alias == "" {
		s.Alias = "fx"
	}
	if s.Risk == "" {
		s.Risk = "low"
	}
	if s.Tools == nil {
		s.Tools = []*mcp.Tool{EchoTool("Return the text.")}
	}
	if s.ArtifactName == "" {
		s.ArtifactName = "server"
	}
	if s.Artifact == nil {
		s.Artifact = []byte("#!/bin/false\nfixture artifact " + s.ID + "\n")
	}
	if s.Argv == nil {
		s.Argv = []string{s.ArtifactName}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, packaging.ArtifactDir), 0o755))
	art := filepath.Join(dir, packaging.ArtifactDir, s.ArtifactName)
	must(os.WriteFile(art, s.Artifact, 0o755))
	artSum := packaging.SHA256Hex(s.Artifact)
	cts, err := packaging.CanonicalLive(s.Tools)
	must(err)
	m := &packaging.Manifest{ManifestVersion: 1,
		Server:        packaging.ServerInfo{ID: s.ID, Revision: s.Revision, Alias: s.Alias, Publisher: "test"},
		Artifact:      packaging.ArtifactInfo{Type: "binary", Reference: "/fixture/" + s.ArtifactName, Version: s.Revision, SHA256: artSum, SizeBytes: int64(len(s.Artifact))},
		Launch:        packaging.Launch{Runtime: "native", Argv: s.Argv},
		Era:           "2025-11-25",
		RiskClass:     s.Risk,
		InstanceScope: []string{"shared"},
		Stateful:      s.Stateful,
		Capabilities:  packaging.Capabilities{Filesystem: []packaging.FilesystemSlot{}, Egress: []packaging.EgressRule{}},
		Expires:       s.Expires,
		Packaging:     packaging.PackagingInfo{Tool: "pkgtest", ToolVersion: "1", BuiltAt: time.Now().UTC().Format(time.RFC3339)},
	}
	for _, ct := range cts {
		tl := packaging.Tool{Name: ct["name"].(string), SideEffect: "read", SourceTrust: "trusted"}
		tl.Description, _ = ct["description"].(string)
		tl.Title, _ = ct["title"].(string)
		tl.DescriptionSHA256 = packaging.SHA256Hex([]byte(tl.Description))
		for k, dst := range map[string]*json.RawMessage{"inputSchema": &tl.InputSchema, "outputSchema": &tl.OutputSchema, "annotations": &tl.Annotations} {
			if v, ok := ct[k]; ok {
				raw, err := json.Marshal(v)
				must(err)
				*dst = raw
			}
		}
		m.Tools = append(m.Tools, tl)
	}
	m.ToolsListSHA256, err = packaging.ToolsDigest(m.CanonicalTools())
	must(err)
	src := packaging.Source{Kind: "archive", URI: "https://example.invalid/" + s.ID + ".tar.gz", SHA256: packaging.SHA256Hex([]byte("source " + s.ID))}
	prov := packaging.Provenance{ProvenanceVersion: 1, ServerID: s.ID, Revision: s.Revision, Artifact: m.Artifact, Source: src, Licenses: []string{"Apache-2.0"},
		Builder: packaging.Builder{Tool: "pkgtest"}, Probe: packaging.ProbeEnvironment{Launcher: "none", Network: "none", EnvNames: []string{}}, BuiltAt: m.Packaging.BuiltAt}
	m.Provenance = packaging.ManifestProvenance{Source: src, Licenses: prov.Licenses}
	if s.Edit != nil {
		s.Edit(m, &prov)
	}
	must(packaging.WriteJSON(filepath.Join(dir, packaging.ProvenanceFile), prov, 0o644))
	provSum, provSize, err := packaging.FileSHA256(filepath.Join(dir, packaging.ProvenanceFile))
	must(err)
	if m.Provenance.StatementSHA256 == "" {
		m.Provenance.StatementSHA256 = provSum
	}
	must(packaging.WriteJSON(filepath.Join(dir, packaging.ManifestFile), m, 0o644))
	manSum, manSize, err := packaging.FileSHA256(filepath.Join(dir, packaging.ManifestFile))
	must(err)
	ix := packaging.Index{IndexVersion: 1, ServerID: s.ID, Revision: s.Revision, RiskClass: m.RiskClass,
		Artifact:   packaging.FileRef{Path: packaging.ArtifactDir + "/" + s.ArtifactName, SHA256: artSum, Size: int64(len(s.Artifact))},
		Manifest:   packaging.FileRef{Path: packaging.ManifestFile, SHA256: manSum, Size: manSize},
		Provenance: packaging.FileRef{Path: packaging.ProvenanceFile, SHA256: provSum, Size: provSize},
		CreatedAt:  time.Now().UTC().Format(time.RFC3339)}
	must(packaging.WriteJSON(filepath.Join(dir, packaging.IndexFile), ix, 0o644))
}

// Signed builds and signs a fixture package.
func Signed(t testing.TB, dir string, k Key, s Spec) string {
	t.Helper()
	Build(t, dir, s)
	if err := packaging.Sign(dir, k.Private, time.Now()); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Enroll adds k as a trust anchor under stateDir.
func Enroll(t testing.TB, stateDir, name string, k Key, classes []string, expires time.Time) {
	t.Helper()
	a, err := packaging.LoadAnchors(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add(name, k.Public, classes, expires, time.Now(), "test"); err != nil {
		t.Fatal(err)
	}
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
}
