package packaging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Package directory layout (FR-5.2, ARCH §6.3). A package is a directory:
//
//	index.json          lists the digests of the artifact, manifest and provenance
//	index.json.minisig  minisign signature over index.json
//	manifest.json       Appendix J manifest
//	provenance.json     provenance statement (FR-14.5)
//	artifact/<file>     the artifact
const (
	IndexFile      = "index.json"
	SignatureFile  = "index.json.minisig"
	ManifestFile   = "manifest.json"
	ProvenanceFile = "provenance.json"
	ArtifactDir    = "artifact"
)

// IndexVersion is the package index format this release writes and reads.
const IndexVersion = 1

// Index is the signed package index.
type Index struct {
	IndexVersion int     `json:"index_version"`
	ServerID     string  `json:"server_id"`
	Revision     string  `json:"revision"`
	RiskClass    string  `json:"risk_class"`
	Artifact     FileRef `json:"artifact"`
	Manifest     FileRef `json:"manifest"`
	Provenance   FileRef `json:"provenance"`
	SignerKeyID  string  `json:"signer_key_id"`
	CreatedAt    string  `json:"created_at"`
}

// FileRef names a file of the package by path (relative to the package
// directory, slash-separated) and digest.
type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Provenance is the provenance statement (FR-14.5, SR-3.2-1). It binds the
// source reference and licenses to the artifact digest; the index lists its
// digest, so the package signature covers it.
type Provenance struct {
	ProvenanceVersion int              `json:"provenance_version"`
	ServerID          string           `json:"server_id"`
	Revision          string           `json:"revision"`
	Artifact          ArtifactInfo     `json:"artifact"`
	Source            Source           `json:"source"`
	Licenses          []string         `json:"licenses"`
	Dependencies      *DependencyLock  `json:"dependencies,omitempty"`
	Builder           Builder          `json:"builder"`
	Probe             ProbeEnvironment `json:"probe"`
	BuiltAt           string           `json:"built_at"`
}

// DependencyLock records the lock file that pinned transitive dependencies
// when the artifact was assembled (npm lock file or pip requirements with
// hashes).
type DependencyLock struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// Builder names the packaging tool and host.
type Builder struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Host    string `json:"host"`
}

// ProbeEnvironment records the conditions of the tool-list probe
// (SR-3.5-1): the launcher, whether network access was removed, and the
// environment variable names the candidate saw.
type ProbeEnvironment struct {
	Launcher string   `json:"launcher"`
	Confined bool     `json:"confined"`
	Network  string   `json:"network"` // "none" or "host"
	EnvNames []string `json:"env_names"`
}

// Package is a package directory read from disk.
type Package struct {
	Dir           string
	Index         Index
	IndexRaw      []byte
	Signature     []byte
	Manifest      *Manifest
	ManifestRaw   []byte
	Provenance    Provenance
	ProvenanceRaw []byte
}

// ArtifactPath is the absolute path of the artifact file.
func (p *Package) ArtifactPath() string {
	return filepath.Join(p.Dir, filepath.FromSlash(p.Index.Artifact.Path))
}

// safeRel refuses index paths that leave the package directory.
func safeRel(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || !fs.ValidPath(p) {
		return fmt.Errorf("path %q is not a relative path inside the package", p)
	}
	return nil
}

func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// FileSHA256 returns the hex SHA-256 and size of a file.
func FileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := newHash()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return h.hex(), n, nil
}

// readPackage reads every component and checks presence (FR-5.2) and the
// listed digests (FR-14.7). It does not check the signature.
func readPackage(dir string) (*Package, error) {
	p := &Package{Dir: dir}
	var err error
	if p.IndexRaw, err = os.ReadFile(filepath.Join(dir, IndexFile)); err != nil {
		return nil, Wrap(ReasonIndexMissing, "package index "+IndexFile+" is missing", err)
	}
	if p.Signature, err = os.ReadFile(filepath.Join(dir, SignatureFile)); err != nil {
		return nil, Wrap(ReasonSignatureMissing, "signature "+SignatureFile+" is missing", err)
	}
	if err := decodeStrict(p.IndexRaw, &p.Index); err != nil {
		return nil, Wrap(ReasonIndexInvalid, "package index is not valid", err)
	}
	ix := p.Index
	if ix.IndexVersion != IndexVersion {
		return nil, Errf(ReasonIndexInvalid, "index_version %d is not supported", ix.IndexVersion)
	}
	if ix.SignerKeyID == "" {
		return nil, Errf(ReasonSignerKeyIDMissing, "the package index names no signer key identifier")
	}
	for _, c := range []struct {
		ref    FileRef
		reason string
		name   string
	}{
		{ix.Manifest, ReasonManifestMissing, "manifest"},
		{ix.Provenance, ReasonProvenanceMissing, "provenance statement"},
		{ix.Artifact, ReasonArtifactMissing, "artifact"},
	} {
		if c.ref.Path == "" || c.ref.SHA256 == "" {
			return nil, Errf(c.reason, "the package index does not list the %s", c.name)
		}
		if err := safeRel(c.ref.Path); err != nil {
			return nil, Wrap(ReasonIndexInvalid, c.name, err)
		}
		path := filepath.Join(dir, filepath.FromSlash(c.ref.Path))
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() {
			return nil, Errf(c.reason, "the %s %s is missing or not a regular file", c.name, c.ref.Path)
		}
	}
	return p, nil
}

// checkDigests verifies every listed digest.
func (p *Package) checkDigests() error {
	for _, c := range []struct {
		ref  FileRef
		name string
	}{{p.Index.Manifest, "manifest"}, {p.Index.Provenance, "provenance statement"}, {p.Index.Artifact, "artifact"}} {
		sum, size, err := FileSHA256(filepath.Join(p.Dir, filepath.FromSlash(c.ref.Path)))
		if err != nil {
			return Wrap(ReasonDigestMismatch, c.name, err)
		}
		if sum != c.ref.SHA256 || (c.ref.Size != 0 && size != c.ref.Size) {
			return Errf(ReasonDigestMismatch, "the %s digest %s does not match the index (%s)", c.name, sum, c.ref.SHA256)
		}
	}
	return nil
}

// loadContents parses the manifest (FR-14.11) and provenance statement and
// checks their bindings to the index (SR-3.1-1, SR-3.2-1).
func (p *Package) loadContents() error {
	var err error
	if p.ManifestRaw, err = os.ReadFile(filepath.Join(p.Dir, filepath.FromSlash(p.Index.Manifest.Path))); err != nil {
		return Wrap(ReasonManifestMissing, "manifest", err)
	}
	if p.Manifest, err = ParseManifest(p.ManifestRaw); err != nil {
		return err
	}
	if p.ProvenanceRaw, err = os.ReadFile(filepath.Join(p.Dir, filepath.FromSlash(p.Index.Provenance.Path))); err != nil {
		return Wrap(ReasonProvenanceMissing, "provenance statement", err)
	}
	if err := decodeStrict(p.ProvenanceRaw, &p.Provenance); err != nil {
		return Wrap(ReasonProvenanceBinding, "provenance statement is not valid", err)
	}
	m, pv, ix := p.Manifest, p.Provenance, p.Index
	if m.Server.ID != ix.ServerID || m.Server.Revision != ix.Revision || m.RiskClass != ix.RiskClass {
		return Errf(ReasonIndexInvalid, "the index names %s@%s (%s) but the manifest is %s@%s (%s)", ix.ServerID, ix.Revision, ix.RiskClass, m.Server.ID, m.Server.Revision, m.RiskClass)
	}
	if m.Artifact.SHA256 != ix.Artifact.SHA256 {
		return Errf(ReasonDigestMismatch, "the manifest artifact digest %s differs from the index (%s)", m.Artifact.SHA256, ix.Artifact.SHA256)
	}
	// SR-3.1-1: source archive reference with digest and SPDX licenses.
	if pv.Source.URI == "" || pv.Source.SHA256 == "" || len(pv.Source.SHA256) != 64 || len(pv.Licenses) == 0 {
		return Errf(ReasonSourceEvidence, "the provenance statement lacks a source reference with digest or SPDX license identifiers")
	}
	// SR-3.2-1: the statement binds the source digest to the artifact digest,
	// and the manifest names the same statement and source.
	switch {
	case pv.ServerID != m.Server.ID || pv.Revision != m.Server.Revision:
		return Errf(ReasonProvenanceBinding, "the provenance statement names %s@%s", pv.ServerID, pv.Revision)
	case pv.Artifact.SHA256 != m.Artifact.SHA256:
		return Errf(ReasonProvenanceBinding, "the provenance statement binds artifact %s, not %s", pv.Artifact.SHA256, m.Artifact.SHA256)
	case pv.Source.SHA256 != m.Provenance.Source.SHA256 || pv.Source.URI != m.Provenance.Source.URI:
		return Errf(ReasonProvenanceBinding, "the provenance statement source differs from the manifest source")
	case m.Provenance.StatementSHA256 != ix.Provenance.SHA256:
		return Errf(ReasonProvenanceBinding, "the manifest statement_sha256 does not name the listed provenance statement")
	}
	return nil
}

// WriteJSON writes v as indented JSON with a trailing newline.
func WriteJSON(path string, v any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(raw, '\n'), mode)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// WriteFileAtomic writes data to path through a temporary file and rename.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	return writeFileAtomic(path, data, mode)
}

// CopyPackage copies a package's listed files into dst, which must not
// exist: index, signature, manifest, provenance and artifact.
func CopyPackage(src, dst string) error {
	raw, err := os.ReadFile(filepath.Join(src, IndexFile))
	if err != nil {
		return Wrap(ReasonIndexMissing, "package index", err)
	}
	var ix Index
	if err := decodeStrict(raw, &ix); err != nil {
		return Wrap(ReasonIndexInvalid, "package index", err)
	}
	files := []string{IndexFile, SignatureFile}
	for _, r := range []FileRef{ix.Manifest, ix.Provenance, ix.Artifact} {
		if err := safeRel(r.Path); err != nil {
			return Wrap(ReasonIndexInvalid, "package index", err)
		}
		files = append(files, r.Path)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s exists", dst)
	}
	// Copy into a hidden sibling and rename, so a library scan never sees
	// a partly copied package.
	tmp, err := os.MkdirTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-")
	if err != nil {
		return err
	}
	for _, f := range files {
		to := filepath.Join(tmp, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			os.RemoveAll(tmp)
			return err
		}
		if err := CopyFile(filepath.Join(src, filepath.FromSlash(f)), to, 0o644); err != nil {
			os.RemoveAll(tmp)
			return err
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil { //nolint:gosec // a package directory is public, like the one it copies
		os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	return nil
}
