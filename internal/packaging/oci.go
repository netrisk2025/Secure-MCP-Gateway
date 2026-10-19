package packaging

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// OCI media types accepted when pulling by digest.
const (
	ociIndexType      = "application/vnd.oci.image.index.v1+json"
	ociManifestType   = "application/vnd.oci.image.manifest.v1+json"
	dockerListType    = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerManifestTyp = "application/vnd.docker.distribution.manifest.v2+json"
)

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ociPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

type ociManifest struct {
	MediaType string          `json:"mediaType"`
	Config    ociDescriptor   `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
	Manifests []ociDescriptor `json:"manifests"`
}

// ociRepo splits an image reference into registry host and repository path,
// applying the Docker Hub defaults.
func ociRepo(name string) (host, repo string) {
	first, rest, ok := strings.Cut(name, "/")
	if !ok || (!strings.ContainsAny(first, ".:") && first != "localhost") {
		repo = name
		if !strings.Contains(repo, "/") {
			repo = "library/" + repo
		}
		return "registry-1.docker.io", repo
	}
	return first, rest
}

type ociClient struct {
	f      *Fetcher
	base   string
	repo   string
	token  string
	tmpDir string
}

func (c *ociClient) get(ctx context.Context, path string, accept []string) (*http.Response, error) {
	do := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
		if err != nil {
			return nil, err
		}
		if len(accept) > 0 {
			req.Header.Set("Accept", strings.Join(accept, ", "))
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		return c.f.client().Do(req)
	}
	resp, err := do()
	if err != nil {
		return nil, Wrap(ReasonFetchFailed, c.base+path, err)
	}
	if resp.StatusCode == http.StatusUnauthorized && c.token == "" {
		chal := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		if err := c.authenticate(ctx, chal); err != nil {
			return nil, err
		}
		if resp, err = do(); err != nil {
			return nil, Wrap(ReasonFetchFailed, c.base+path, err)
		}
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, Errf(ReasonFetchFailed, "%s%s: HTTP %d", c.base, path, resp.StatusCode)
	}
	return resp, nil
}

// authenticate obtains an anonymous bearer token from the challenge.
func (c *ociClient) authenticate(ctx context.Context, challenge string) error {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return Wrap(ReasonFetchFailed, "OCI registry", errOCIAuth)
	}
	kv := map[string]string{}
	for _, part := range strings.Split(params, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			kv[k] = strings.Trim(v, `"`)
		}
	}
	realm, err := url.Parse(kv["realm"])
	if err != nil || (realm.Scheme != "https" && !c.f.OCIPlainHTTP) {
		return Errf(ReasonFetchFailed, "OCI registry token realm %q is not https", kv["realm"])
	}
	q := realm.Query()
	if kv["service"] != "" {
		q.Set("service", kv["service"])
	}
	scope := kv["scope"]
	if scope == "" {
		scope = "repository:" + c.repo + ":pull"
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := c.f.getJSON(ctx, realm.String(), &tok); err != nil {
		return err
	}
	c.token = tok.Token
	if c.token == "" {
		c.token = tok.AccessToken
	}
	if c.token == "" {
		return Wrap(ReasonFetchFailed, "OCI registry", errOCIAuth)
	}
	return nil
}

// manifest fetches and verifies a manifest or index by digest.
func (c *ociClient) manifest(ctx context.Context, digest string) ([]byte, *ociManifest, error) {
	resp, err := c.get(ctx, "/v2/"+c.repo+"/manifests/"+digest, []string{ociIndexType, ociManifestType, dockerListType, dockerManifestTyp})
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, Wrap(ReasonFetchFailed, "manifest", err)
	}
	if "sha256:"+SHA256Hex(raw) != digest {
		return nil, nil, Errf(ReasonDigestMismatch, "manifest digest sha256:%s does not match %s", SHA256Hex(raw), digest)
	}
	var m ociManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, Wrap(ReasonFetchFailed, "manifest", err)
	}
	if m.MediaType == "" {
		m.MediaType = resp.Header.Get("Content-Type")
	}
	return raw, &m, nil
}

// blob downloads and verifies one blob into the temporary directory.
func (c *ociClient) blob(ctx context.Context, d ociDescriptor) (string, error) {
	if !ociDigest.MatchString(d.Digest) {
		return "", Errf(ReasonFetchFailed, "unsupported blob digest %q", d.Digest)
	}
	resp, err := c.get(ctx, "/v2/"+c.repo+"/blobs/"+d.Digest, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	p := filepath.Join(c.tmpDir, strings.TrimPrefix(d.Digest, "sha256:"))
	out, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := newHash()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, c.f.maxBytes()+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", Wrap(ReasonFetchFailed, d.Digest, err)
	}
	if "sha256:"+h.hex() != d.Digest || (d.Size > 0 && n != d.Size) {
		return "", Errf(ReasonDigestMismatch, "blob %s has digest sha256:%s", d.Digest, h.hex())
	}
	return p, nil
}

// fetchOCI pulls an image by manifest digest and writes it as an OCI image
// layout tar (podman's oci-archive transport). For an index it selects the
// linux image of this host's architecture.
func (f *Fetcher) fetchOCI(ctx context.Context, r ArtifactRef, dir string) (*Fetched, error) {
	host, repo := ociRepo(r.Name)
	scheme := "https"
	if f.OCIPlainHTTP {
		scheme = "http"
	}
	tmp, err := os.MkdirTemp(dir, "oci-blobs-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	c := &ociClient{f: f, base: scheme + "://" + host, repo: repo, tmpDir: tmp}
	blobs := map[string][]byte{} // small JSON blobs by digest
	topRaw, top, err := c.manifest(ctx, r.Integrity)
	if err != nil {
		return nil, err
	}
	blobs[r.Integrity] = topRaw
	imgDigest, img, imgRaw := r.Integrity, top, topRaw
	if top.MediaType == ociIndexType || top.MediaType == dockerListType || len(top.Manifests) > 0 {
		var pick *ociDescriptor
		for i := range top.Manifests {
			p := top.Manifests[i].Platform
			if p != nil && p.OS == "linux" && p.Architecture == runtime.GOARCH {
				pick = &top.Manifests[i]
				break
			}
		}
		if pick == nil {
			return nil, Errf(ReasonFetchFailed, "image index %s has no linux/%s image", r.Integrity, runtime.GOARCH)
		}
		if imgRaw, img, err = c.manifest(ctx, pick.Digest); err != nil {
			return nil, err
		}
		imgDigest = pick.Digest
		blobs[imgDigest] = imgRaw
	}
	files := map[string]string{} // digest -> downloaded path
	labels := map[string]string{}
	for _, d := range append([]ociDescriptor{img.Config}, img.Layers...) {
		p, err := c.blob(ctx, d)
		if err != nil {
			return nil, err
		}
		files[d.Digest] = p
		if d.Digest == img.Config.Digest {
			var cfg struct {
				Config struct {
					Labels map[string]string `json:"Labels"`
				} `json:"config"`
			}
			if raw, err := os.ReadFile(p); err == nil && json.Unmarshal(raw, &cfg) == nil {
				labels = cfg.Config.Labels
			}
		}
	}
	mt := img.MediaType
	if mt == "" {
		mt = ociManifestType
	}
	layoutIndex, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ociIndexType, "manifests": []ociDescriptor{{
		MediaType: mt, Digest: imgDigest, Size: int64(len(imgRaw)),
		Annotations: map[string]string{"org.opencontainers.image.ref.name": r.Version},
	}}})
	if err != nil {
		return nil, err
	}
	name := strings.ReplaceAll(repo, "/", "_") + "-" + r.Version + ".oci.tar"
	out := filepath.Join(dir, name)
	if err := writeOCILayout(out, layoutIndex, blobs, files); err != nil {
		return nil, err
	}
	s256, n, err := FileSHA256(out)
	if err != nil {
		return nil, err
	}
	fe := &Fetched{Path: out, SHA256: s256, Size: n, RegistryIntegrity: imgDigest, FileName: name}
	if src := labels["org.opencontainers.image.source"]; src != "" {
		fe.SourceKind, fe.SourceURI = "oci-source-label", src
	}
	return fe, nil
}

// writeOCILayout writes a deterministic OCI image layout tar.
func writeOCILayout(path string, index []byte, small map[string][]byte, files map[string]string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(f)
	epoch := time.Unix(0, 0)
	add := func(name string, size int64, r io.Reader) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, ModTime: epoch, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := io.Copy(tw, r)
		return err
	}
	layout := []byte(`{"imageLayoutVersion":"1.0.0"}`)
	type entry struct {
		name string
		data []byte
		path string
	}
	var entries []entry
	entries = append(entries, entry{name: "oci-layout", data: layout}, entry{name: "index.json", data: index})
	var blobNames []string
	byName := map[string]entry{}
	for d, b := range small {
		n := "blobs/sha256/" + strings.TrimPrefix(d, "sha256:")
		byName[n] = entry{name: n, data: b}
		blobNames = append(blobNames, n)
	}
	for d, p := range files {
		n := "blobs/sha256/" + strings.TrimPrefix(d, "sha256:")
		if _, dup := byName[n]; dup {
			continue
		}
		byName[n] = entry{name: n, path: p}
		blobNames = append(blobNames, n)
	}
	sort.Strings(blobNames)
	for _, n := range blobNames {
		entries = append(entries, byName[n])
	}
	for _, d := range []string{"blobs/", "blobs/sha256/"} {
		if err := tw.WriteHeader(&tar.Header{Name: d, Mode: 0o755, ModTime: epoch, Typeflag: tar.TypeDir, Format: tar.FormatPAX}); err != nil {
			f.Close()
			return err
		}
	}
	for _, e := range entries {
		var err error
		if e.path == "" {
			err = add(e.name, int64(len(e.data)), bytes.NewReader(e.data))
		} else {
			var bf *os.File
			if bf, err = os.Open(e.path); err == nil {
				var st os.FileInfo
				if st, err = bf.Stat(); err == nil {
					err = add(e.name, st.Size(), bf)
				}
				bf.Close()
			}
		}
		if err != nil {
			f.Close()
			return fmt.Errorf("write %s: %w", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
