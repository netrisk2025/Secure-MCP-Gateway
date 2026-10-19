package packaging

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ArtifactRef is a pinned artifact reference (FR-14.1, FR-14.2).
//
//	npm     Name is the package name (@scope/name), Version the exact
//	        version, Integrity the registry "sha512-..." value and/or
//	        SHA256 the tarball digest.
//	pypi    Name is the project, Version the exact version, SHA256 the
//	        digest of the distribution file (a wheel) to use.
//	oci     Name is the image repository (registry/path), Version the tag
//	        for reference, Integrity the image manifest digest
//	        "sha256:...".
//	binary  Name is a local path or an https URL, Version the operator's
//	        version label, SHA256 the file digest.
type ArtifactRef struct {
	Type      string `json:"type"`
	Name      string `json:"reference"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256,omitempty"`
	Integrity string `json:"integrity,omitempty"`
}

var (
	hex64      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	exactVer   = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*([-+._]?[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)
	distTags   = []string{"latest", "next", "stable", "beta", "alpha", "canary", "rc", "dev", "edge", "nightly", "main", "master", "head"}
	npmIntegRE = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)
	ociDigest  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// Check refuses references without an exact version or a digest (FR-14.2):
// version ranges, dist-tags such as latest, image tags without a digest
// and references without any digest.
func (r ArtifactRef) Check() error {
	if !slices.Contains([]string{"npm", "pypi", "oci", "binary"}, r.Type) {
		return Errf(ReasonUnpinned, "artifact type %q is not one of npm, pypi, oci, binary", r.Type)
	}
	if r.Name == "" {
		return Errf(ReasonUnpinned, "the artifact reference names no package, image or file")
	}
	v := strings.TrimSpace(r.Version)
	switch {
	case v == "":
		return Errf(ReasonUnpinned, "the %s reference %s names no exact version", r.Type, r.Name)
	case slices.Contains(distTags, strings.ToLower(v)):
		return Errf(ReasonUnpinned, "version %q is a dist-tag, not an exact version", v)
	case strings.ContainsAny(v, "^~*<>=|, ") || strings.Contains(v, "x.") || strings.HasSuffix(v, ".x") || strings.Contains(v, " - "):
		return Errf(ReasonUnpinned, "version %q is a range, not an exact version", v)
	case !exactVer.MatchString(v):
		return Errf(ReasonUnpinned, "version %q is not an exact version", v)
	}
	if r.SHA256 != "" && !hex64.MatchString(r.SHA256) {
		return Errf(ReasonUnpinned, "sha256 %q is not 64 lowercase hex digits", r.SHA256)
	}
	switch r.Type {
	case "npm":
		if r.Integrity != "" && !npmIntegRE.MatchString(r.Integrity) {
			return Errf(ReasonUnpinned, "npm integrity must be a sha512-... value")
		}
		if r.Integrity == "" && r.SHA256 == "" {
			return Errf(ReasonUnpinned, "the npm reference %s@%s has no digest (integrity or sha256)", r.Name, v)
		}
	case "pypi", "binary":
		if r.SHA256 == "" {
			return Errf(ReasonUnpinned, "the %s reference %s has no sha256 digest", r.Type, r.Name)
		}
		if r.Type == "binary" && strings.HasPrefix(r.Name, "http://") {
			return Errf(ReasonUnpinned, "binary downloads must use https")
		}
	case "oci":
		if strings.Contains(r.Name, "@") {
			return Errf(ReasonUnpinned, "give the image digest in integrity, not in the reference")
		}
		if !ociDigest.MatchString(r.Integrity) {
			return Errf(ReasonUnpinned, "the OCI reference %s:%s has no image manifest digest (integrity sha256:...)", r.Name, v)
		}
	}
	return nil
}

// Fetcher retrieves artifacts over X-17. The base URLs are overridable for
// mirrors and tests.
type Fetcher struct {
	HTTP        *http.Client
	NPMRegistry string // default https://registry.npmjs.org
	PyPIIndex   string // default https://pypi.org
	// OCIPlainHTTP talks plain HTTP to OCI registries (tests only).
	OCIPlainHTTP bool
	// MaxBytes bounds one download (default 1 GiB).
	MaxBytes int64
}

func (f *Fetcher) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

func (f *Fetcher) maxBytes() int64 {
	if f.MaxBytes > 0 {
		return f.MaxBytes
	}
	return 1 << 30
}

// Fetched is a downloaded file and what was learned about it.
type Fetched struct {
	Path              string
	SHA256            string
	Size              int64
	RegistryIntegrity string
	// SourceURI and SourceSHA256 are a source reference the registry
	// supplied (npm tarball, PyPI sdist), when it supplied one.
	SourceKind   string
	SourceURI    string
	SourceSHA256 string
	FileName     string
}

// download writes the body of u into dir and returns its SHA-256 and
// SHA-512.
func (f *Fetcher) download(ctx context.Context, u, dir, name string, hdr http.Header) (string, string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", 0, "", err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return "", "", 0, "", Wrap(ReasonFetchFailed, u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, "", Errf(ReasonFetchFailed, "%s: HTTP %d", u, resp.StatusCode)
	}
	p := filepath.Join(dir, name)
	out, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", 0, "", err
	}
	h256, h512 := newHash(), sha512.New()
	n, err := io.Copy(io.MultiWriter(out, h256, h512), io.LimitReader(resp.Body, f.maxBytes()+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", "", 0, "", Wrap(ReasonFetchFailed, u, err)
	}
	if n > f.maxBytes() {
		return "", "", 0, "", Errf(ReasonFetchFailed, "%s exceeds %d bytes", u, f.maxBytes())
	}
	return h256.hex(), "sha512-" + base64.StdEncoding.EncodeToString(h512.Sum(nil)), n, p, nil
}

func (f *Fetcher) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client().Do(req)
	if err != nil {
		return Wrap(ReasonFetchFailed, u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Errf(ReasonFetchFailed, "%s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

// Fetch retrieves the artifact into dir and verifies its digest (FR-14.1).
func (f *Fetcher) Fetch(ctx context.Context, r ArtifactRef, dir string) (*Fetched, error) {
	if err := r.Check(); err != nil {
		return nil, err
	}
	switch r.Type {
	case "npm":
		return f.fetchNPM(ctx, r, dir)
	case "pypi":
		return f.fetchPyPI(ctx, r, dir)
	case "oci":
		return f.fetchOCI(ctx, r, dir)
	default:
		return f.fetchBinary(ctx, r, dir)
	}
}

func (f *Fetcher) fetchNPM(ctx context.Context, r ArtifactRef, dir string) (*Fetched, error) {
	reg := strings.TrimSuffix(f.NPMRegistry, "/")
	if reg == "" {
		reg = "https://registry.npmjs.org"
	}
	base := path.Base(r.Name)
	u := fmt.Sprintf("%s/%s/-/%s-%s.tgz", reg, r.Name, base, r.Version)
	s256, s512, n, p, err := f.download(ctx, u, dir, base+"-"+r.Version+".tgz", nil)
	if err != nil {
		return nil, err
	}
	if r.Integrity != "" && s512 != r.Integrity {
		return nil, Errf(ReasonDigestMismatch, "%s: integrity %s does not match the pinned %s", u, s512, r.Integrity)
	}
	if r.SHA256 != "" && s256 != r.SHA256 {
		return nil, Errf(ReasonDigestMismatch, "%s: sha256 %s does not match the pinned %s", u, s256, r.SHA256)
	}
	return &Fetched{Path: p, SHA256: s256, Size: n, RegistryIntegrity: s512, SourceKind: "registry-tarball", SourceURI: u, SourceSHA256: s256, FileName: filepath.Base(p)}, nil
}

type pypiRelease struct {
	URLs []struct {
		Filename    string            `json:"filename"`
		URL         string            `json:"url"`
		PackageType string            `json:"packagetype"`
		Digests     map[string]string `json:"digests"`
	} `json:"urls"`
}

func (f *Fetcher) fetchPyPI(ctx context.Context, r ArtifactRef, dir string) (*Fetched, error) {
	idx := strings.TrimSuffix(f.PyPIIndex, "/")
	if idx == "" {
		idx = "https://pypi.org"
	}
	var rel pypiRelease
	if err := f.getJSON(ctx, fmt.Sprintf("%s/pypi/%s/%s/json", idx, url.PathEscape(r.Name), url.PathEscape(r.Version)), &rel); err != nil {
		return nil, err
	}
	var file, sdistURL, sdistSHA string
	var fileURL string
	for _, u := range rel.URLs {
		if u.PackageType == "sdist" {
			sdistURL, sdistSHA = u.URL, u.Digests["sha256"]
		}
		if u.Digests["sha256"] == r.SHA256 {
			file, fileURL = u.Filename, u.URL
		}
	}
	if fileURL == "" {
		return nil, Errf(ReasonDigestMismatch, "%s %s has no distribution file with sha256 %s", r.Name, r.Version, r.SHA256)
	}
	if strings.ContainsAny(file, `/\`) || file == "" {
		return nil, Errf(ReasonFetchFailed, "invalid distribution file name %q", file)
	}
	s256, _, n, p, err := f.download(ctx, fileURL, dir, file, nil)
	if err != nil {
		return nil, err
	}
	if s256 != r.SHA256 {
		return nil, Errf(ReasonDigestMismatch, "%s: sha256 %s does not match the pinned %s", fileURL, s256, r.SHA256)
	}
	fe := &Fetched{Path: p, SHA256: s256, Size: n, RegistryIntegrity: "sha256:" + s256, FileName: file}
	if sdistURL != "" && hex64.MatchString(sdistSHA) {
		fe.SourceKind, fe.SourceURI, fe.SourceSHA256 = "sdist", sdistURL, sdistSHA
	}
	return fe, nil
}

func (f *Fetcher) fetchBinary(ctx context.Context, r ArtifactRef, dir string) (*Fetched, error) {
	name := path.Base(r.Name)
	if strings.HasPrefix(r.Name, "https://") {
		u, err := url.Parse(r.Name)
		if err != nil {
			return nil, Wrap(ReasonFetchFailed, r.Name, err)
		}
		name = path.Base(u.Path)
	}
	if name == "" || name == "." || name == "/" || strings.ContainsAny(name, `\`) {
		return nil, Errf(ReasonFetchFailed, "cannot derive a file name from %s", r.Name)
	}
	var s256, p string
	var n int64
	var err error
	if strings.HasPrefix(r.Name, "https://") {
		s256, _, n, p, err = f.download(ctx, r.Name, dir, name, nil)
		if err != nil {
			return nil, err
		}
	} else {
		p = filepath.Join(dir, name)
		if err := CopyFile(r.Name, p, 0o600); err != nil {
			return nil, Wrap(ReasonFetchFailed, r.Name, err)
		}
		if s256, n, err = FileSHA256(p); err != nil {
			return nil, err
		}
	}
	if s256 != r.SHA256 {
		return nil, Errf(ReasonDigestMismatch, "%s: sha256 %s does not match the pinned %s", r.Name, s256, r.SHA256)
	}
	return &Fetched{Path: p, SHA256: s256, Size: n, FileName: name}, nil
}

// errOCIAuth is returned when a registry asks for credentials the fetcher
// does not have.
var errOCIAuth = errors.New("registry requires credentials")
