package packaging

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"path/filepath"
	"runtime"
	"slices"

	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// RecipeVersion is the packaging recipe format this release reads.
const RecipeVersion = 1

// Recipe is the operator's input to `smcpctl package build`: the pinned
// artifact reference, how to launch it, and the classification the
// operator assigns (FR-14.1, FR-14.3). Paths are relative to the recipe
// file.
type Recipe struct {
	RecipeVersion int             `json:"recipe_version"`
	Server        ServerInfo      `json:"server"`
	Artifact      ArtifactRef     `json:"artifact"`
	Dependencies  *RecipeDeps     `json:"dependencies,omitempty"`
	Launch        Launch          `json:"launch"`
	RiskClass     string          `json:"risk_class"`
	InstanceScope []string        `json:"instance_scope"`
	Stateful      bool            `json:"stateful,omitempty"`
	Tools         RecipeTools     `json:"tools"`
	Capabilities  Capabilities    `json:"capabilities"`
	Secrets       []SecretSlot    `json:"secrets,omitempty"`
	BehaviorHints json.RawMessage `json:"behavior_hints,omitempty"`
	Source        *RecipeSource   `json:"source,omitempty"`
	Licenses      []string        `json:"licenses"`
	Expires       string          `json:"expires,omitempty"`
	Attestations  *Attestations   `json:"attestations,omitempty"`
	OperatorNote  string          `json:"operator_note,omitempty"`
	Probe         *RecipeProbe    `json:"probe,omitempty"`

	dir string
}

// RecipeProbe prepares the throwaway slot directories of the probe run.
// RepoInit names slots to initialize as empty Git repositories (for
// servers that refuse to start on a plain directory); it runs the git tool
// on the packaging host only.
type RecipeProbe struct {
	RepoInit []string `json:"repo_init,omitempty"`
}

// RecipeDeps pins transitive dependencies: an npm lock file with its
// package.json, or a pip requirements file with hashes.
type RecipeDeps struct {
	NPMPackageJSON  string `json:"npm_package_json,omitempty"`
	NPMLockfile     string `json:"npm_lockfile,omitempty"`
	PipRequirements string `json:"pip_requirements,omitempty"`
}

// RecipeTools classifies the tools found by the probe.
type RecipeTools struct {
	Default   ToolClass            `json:"default"`
	Overrides map[string]ToolClass `json:"overrides,omitempty"`
	// Expect lists tools the probe must find; packaging fails otherwise.
	Expect []string `json:"expect,omitempty"`
}

// ToolClass is the operator classification of a tool (CP-44).
type ToolClass struct {
	SideEffect  string `json:"side_effect,omitempty"`
	SourceTrust string `json:"source_trust,omitempty"`
	RiskClass   string `json:"risk_class,omitempty"`
}

// RecipeSource is an operator-supplied source reference. Either SHA256 or
// Path (a local copy of the source archive, digested at build) is given.
type RecipeSource struct {
	Kind      string `json:"kind"`
	URI       string `json:"uri"`
	SHA256    string `json:"sha256,omitempty"`
	Path      string `json:"path,omitempty"`
	VCSCommit string `json:"vcs_commit,omitempty"`
}

// LoadRecipe reads a recipe file.
func LoadRecipe(file string) (*Recipe, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var r Recipe
	if err := decodeStrict(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	r.dir = filepath.Dir(abs)
	return &r, nil
}

// SetDir sets the directory relative recipe paths resolve against.
func (r *Recipe) SetDir(d string) { r.dir = d }

func (r *Recipe) path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(r.dir, p)
}

// BuildOptions configure Build.
type BuildOptions struct {
	Fetcher  *Fetcher
	Launcher pipeline.Launcher // probe launcher (default unconfined subprocess)
	Interp   Interpreters
	Now      time.Time
	Version  string // smcpctl version
	// NPM and Python run dependency installation at packaging time only.
	NPM    string
	Python string
	Log    io.Writer
}

// Build materializes the artifact, probes it and writes an unsigned
// package into out (FR-14.1, FR-14.3, FR-14.5). out must not exist.
func Build(ctx context.Context, r *Recipe, out string, o BuildOptions) (*Package, error) {
	if o.Fetcher == nil {
		o.Fetcher = &Fetcher{}
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if r.RecipeVersion != RecipeVersion {
		return nil, fmt.Errorf("recipe_version %d is not supported (want %d)", r.RecipeVersion, RecipeVersion)
	}
	if err := r.Artifact.Check(); err != nil {
		return nil, err
	}
	if err := CheckArgv(r.Launch.Runtime, r.Launch.Argv); err != nil {
		return nil, err
	}
	if r.Server.Revision == "" {
		r.Server.Revision = strings.TrimPrefix(r.Artifact.Version, "v")
	}
	if !ValidID(r.Server.ID, r.Server.Revision) {
		return nil, fmt.Errorf("server id %q or revision %q is not valid", r.Server.ID, r.Server.Revision)
	}
	if err := os.Mkdir(out, 0o755); err != nil {
		return nil, fmt.Errorf("output directory: %w", err)
	}
	if err := os.Mkdir(filepath.Join(out, ArtifactDir), 0o755); err != nil {
		return nil, err
	}
	work, cleanup, err := ThrowawayDir("smcp-package-")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	fmt.Fprintf(o.Log, "fetching %s %s %s\n", r.Artifact.Type, r.Artifact.Name, r.Artifact.Version)
	fe, err := o.Fetcher.Fetch(ctx, r.Artifact, work)
	if err != nil {
		return nil, err
	}
	art, depLock, err := r.assemble(ctx, fe, work, out, o)
	if err != nil {
		return nil, err
	}
	artSum, artSize, err := FileSHA256(art)
	if err != nil {
		return nil, err
	}

	// Probe the artifact as it will be installed.
	probeDir := filepath.Join(work, "probe")
	if err := os.Mkdir(probeDir, 0o700); err != nil {
		return nil, err
	}
	in := LaunchInput{Manifest: r.draftManifest(), Alias: r.Server.Alias, WorkDir: probeDir, Interp: o.Interp, Slots: map[string]string{}}
	switch r.Artifact.Type {
	case "oci":
		in.Archive = art
	case "binary":
		in.Root = filepath.Join(work, "tree")
		if err := os.Mkdir(in.Root, 0o755); err != nil {
			return nil, err
		}
		if err := CopyFile(art, filepath.Join(in.Root, filepath.Base(art)), 0o555); err != nil {
			return nil, err
		}
	default:
		in.Root = filepath.Join(work, "tree")
		if err := ExtractTarGz(art, in.Root, ""); err != nil {
			return nil, err
		}
	}
	for _, s := range r.Capabilities.Filesystem {
		d := filepath.Join(work, "slot-"+s.Slot)
		if err := os.Mkdir(d, 0o700); err != nil {
			return nil, err
		}
		if o.Launcher != nil && o.Launcher.Confined() {
			// A sandboxed probe runs under a subordinate UID; the empty
			// slot directory must be searchable by it.
			if err := os.Chmod(d, 0o755); err != nil { // #nosec G302 -- an empty throwaway directory
				return nil, err
			}
		}
		in.Slots[s.Slot] = d
		if r.Probe != nil && slices.Contains(r.Probe.RepoInit, s.Slot) {
			if err := runTool(ctx, d, minimalEnv(), o.Log, "git", "init", "-q", d); err != nil {
				return nil, fmt.Errorf("probe slot %s: %w", s.Slot, err)
			}
		}
	}
	spec, err := ResolveLaunch(in)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(o.Log, "probing %s (launcher %s)\n", spec.Command, launcherName(o.Launcher))
	pr, err := Probe(ctx, spec, ProbeOptions{Launcher: o.Launcher})
	if err != nil {
		return nil, err
	}

	m := r.draftManifest()
	m.Era = pr.Era
	m.Artifact = ArtifactInfo{Type: r.Artifact.Type, Reference: r.Artifact.Name, Version: r.Artifact.Version, SHA256: artSum,
		RegistryIntegrity: fe.RegistryIntegrity, SizeBytes: artSize}
	if r.Artifact.Type == "binary" {
		m.Artifact.RegistryIntegrity = "sha256:" + fe.SHA256
	}
	if m.Tools, err = r.classify(pr.Tools); err != nil {
		return nil, err
	}
	if m.ToolsListSHA256, err = ToolsDigest(m.CanonicalTools()); err != nil {
		return nil, err
	}

	src, err := r.source(fe)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	prov := Provenance{ProvenanceVersion: 1, ServerID: m.Server.ID, Revision: m.Server.Revision, Artifact: m.Artifact, Source: src,
		Licenses: r.Licenses, Dependencies: depLock, Builder: Builder{Tool: "smcpctl package", Version: o.Version, Host: host + " " + runtime.GOOS + "/" + runtime.GOARCH},
		Probe: pr.Env, BuiltAt: o.Now.UTC().Format(time.RFC3339)}
	if err := WriteJSON(filepath.Join(out, ProvenanceFile), prov, 0o644); err != nil {
		return nil, err
	}
	provSum, provSize, err := FileSHA256(filepath.Join(out, ProvenanceFile))
	if err != nil {
		return nil, err
	}
	m.Provenance = ManifestProvenance{Source: src, Licenses: r.Licenses, StatementSHA256: provSum}
	m.Packaging = PackagingInfo{Tool: "smcpctl package", ToolVersion: o.Version, BuiltAt: o.Now.UTC().Format(time.RFC3339), OperatorNote: r.OperatorNote}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if _, err := ParseManifest(raw); err != nil {
		return nil, fmt.Errorf("generated manifest is not valid: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(out, ManifestFile), raw, 0o644); err != nil {
		return nil, err
	}
	manSum, manSize, err := FileSHA256(filepath.Join(out, ManifestFile))
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(out, art)
	if err != nil {
		return nil, err
	}
	ix := Index{IndexVersion: IndexVersion, ServerID: m.Server.ID, Revision: m.Server.Revision, RiskClass: m.RiskClass,
		Artifact:   FileRef{Path: filepath.ToSlash(rel), SHA256: artSum, Size: artSize},
		Manifest:   FileRef{Path: ManifestFile, SHA256: manSum, Size: manSize},
		Provenance: FileRef{Path: ProvenanceFile, SHA256: provSum, Size: provSize},
		CreatedAt:  o.Now.UTC().Format(time.RFC3339)}
	if err := WriteJSON(filepath.Join(out, IndexFile), ix, 0o644); err != nil {
		return nil, err
	}
	return &Package{Dir: out, Index: ix, Manifest: m, ManifestRaw: raw, Provenance: prov}, nil
}

func launcherName(l pipeline.Launcher) string {
	if l == nil {
		return "subprocess"
	}
	return l.Name()
}

// draftManifest fills the operator-supplied parts of the manifest.
func (r *Recipe) draftManifest() *Manifest {
	caps := r.Capabilities
	if caps.Filesystem == nil {
		caps.Filesystem = []FilesystemSlot{}
	}
	if caps.Egress == nil {
		caps.Egress = []EgressRule{}
	}
	return &Manifest{ManifestVersion: ManifestVersion, Server: r.Server, Launch: r.Launch, RiskClass: r.RiskClass, InstanceScope: r.InstanceScope,
		Stateful: r.Stateful, Capabilities: caps, Secrets: r.Secrets, BehaviorHints: r.BehaviorHints, Attestations: r.Attestations, Expires: r.Expires}
}

// classify turns the live tools into manifest tools with the operator's
// classification.
func (r *Recipe) classify(live []*mcp.Tool) ([]Tool, error) {
	cts, err := CanonicalLive(live)
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	var out []Tool
	for _, ct := range cts {
		name := ct["name"].(string)
		found[name] = true
		cls := r.Tools.Default
		if ov, ok := r.Tools.Overrides[name]; ok {
			if ov.SideEffect != "" {
				cls.SideEffect = ov.SideEffect
			}
			if ov.SourceTrust != "" {
				cls.SourceTrust = ov.SourceTrust
			}
			if ov.RiskClass != "" {
				cls.RiskClass = ov.RiskClass
			}
		}
		if cls.SideEffect == "" || cls.SourceTrust == "" {
			return nil, fmt.Errorf("tool %q has no side_effect or source_trust classification; set tools.default or tools.overrides", name)
		}
		t := Tool{Name: name, SideEffect: cls.SideEffect, SourceTrust: cls.SourceTrust, RiskClass: cls.RiskClass}
		t.Title, _ = ct["title"].(string)
		t.Description, _ = ct["description"].(string)
		t.DescriptionSHA256 = SHA256Hex([]byte(t.Description))
		for k, dst := range map[string]*json.RawMessage{"inputSchema": &t.InputSchema, "outputSchema": &t.OutputSchema, "annotations": &t.Annotations} {
			if v, ok := ct[k]; ok {
				raw, err := json.Marshal(v)
				if err != nil {
					return nil, err
				}
				*dst = raw
			}
		}
		if t.InputSchema == nil {
			return nil, fmt.Errorf("tool %q has no inputSchema", name)
		}
		out = append(out, t)
	}
	for name := range r.Tools.Overrides {
		if !found[name] {
			return nil, fmt.Errorf("tools.overrides names %q, which the server does not list", name)
		}
	}
	for _, name := range r.Tools.Expect {
		if !found[name] {
			return nil, fmt.Errorf("the server does not list the expected tool %q", name)
		}
	}
	return out, nil
}

// source picks the provenance source: the operator's, else what the
// registry supplied.
func (r *Recipe) source(fe *Fetched) (Source, error) {
	if s := r.Source; s != nil {
		out := Source{Kind: s.Kind, URI: s.URI, SHA256: s.SHA256, VCSCommit: s.VCSCommit}
		if s.Path != "" {
			sum, _, err := FileSHA256(r.path(s.Path))
			if err != nil {
				return out, fmt.Errorf("source archive: %w", err)
			}
			if out.SHA256 != "" && out.SHA256 != sum {
				return out, Errf(ReasonDigestMismatch, "source archive digest %s differs from the recipe %s", sum, out.SHA256)
			}
			out.SHA256 = sum
		}
		if out.URI == "" || !hex64.MatchString(out.SHA256) {
			return out, Errf(ReasonSourceEvidence, "the recipe source needs a uri and a sha256 or path")
		}
		return out, nil
	}
	if fe.SourceURI != "" && hex64.MatchString(fe.SourceSHA256) {
		return Source{Kind: fe.SourceKind, URI: fe.SourceURI, SHA256: fe.SourceSHA256}, nil
	}
	return Source{}, Errf(ReasonSourceEvidence, "the %s artifact has no registry source reference; add a source to the recipe", r.Artifact.Type)
}

// assemble produces the artifact file under out/artifact.
func (r *Recipe) assemble(ctx context.Context, fe *Fetched, work, out string, o BuildOptions) (string, *DependencyLock, error) {
	artDir := filepath.Join(out, ArtifactDir)
	switch r.Artifact.Type {
	case "binary", "oci":
		dst := filepath.Join(artDir, fe.FileName)
		mode := os.FileMode(0o644)
		if r.Artifact.Type == "binary" {
			mode = 0o755
			if want := r.Launch.Argv[0]; want != fe.FileName {
				return "", nil, fmt.Errorf("launch argv[0] %q must name the binary file %q", want, fe.FileName)
			}
		}
		return dst, nil, CopyFile(fe.Path, dst, mode)
	}
	stage := filepath.Join(work, "stage")
	if err := os.Mkdir(stage, 0o755); err != nil {
		return "", nil, err
	}
	var lock *DependencyLock
	var err error
	switch r.Artifact.Type {
	case "npm":
		lock, err = r.stageNPM(ctx, fe, stage, o)
	case "pypi":
		lock, err = r.stagePyPI(ctx, fe, stage, o)
	}
	if err != nil {
		return "", nil, err
	}
	dst := filepath.Join(artDir, strings.ReplaceAll(strings.TrimPrefix(r.Artifact.Name, "@"), "/", "-")+"-"+r.Artifact.Version+".tar.gz")
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) //nolint:gosec // package files are public
	if err != nil {
		return "", nil, err
	}
	if err := TarGzDir(stage, f); err != nil {
		f.Close()
		return "", nil, err
	}
	return dst, lock, f.Close()
}

func runTool(ctx context.Context, dir string, env []string, logw io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, truncate(buf.String(), 4000))
	}
	fmt.Fprint(logw, buf.String())
	return nil
}

func minimalEnv(extra ...string) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	return append(env, extra...)
}

// stageNPM installs the package tree. With a lock file the dependency
// closure is installed by `npm ci` from the lock (integrity-checked, no
// install scripts); without one only the package itself is unpacked.
func (r *Recipe) stageNPM(ctx context.Context, fe *Fetched, stage string, o BuildOptions) (*DependencyLock, error) {
	d := r.Dependencies
	if d == nil || d.NPMLockfile == "" {
		dest := filepath.Join(stage, "node_modules", filepath.FromSlash(r.Artifact.Name))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return nil, err
		}
		if err := ExtractTarGz(fe.Path, dest, "package/"); err != nil {
			return nil, err
		}
		makeOwnerWritable(stage)
		return nil, nil
	}
	if d.NPMPackageJSON == "" {
		return nil, errors.New("dependencies.npm_lockfile needs dependencies.npm_package_json")
	}
	lockRaw, err := os.ReadFile(r.path(d.NPMLockfile))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		return nil, fmt.Errorf("npm lock file: %w", err)
	}
	ent, ok := lock.Packages["node_modules/"+r.Artifact.Name]
	if !ok || ent.Version != r.Artifact.Version || ent.Integrity != fe.RegistryIntegrity {
		return nil, Errf(ReasonDigestMismatch, "the lock file does not pin %s@%s with integrity %s", r.Artifact.Name, r.Artifact.Version, fe.RegistryIntegrity)
	}
	if err := CopyFile(r.path(d.NPMPackageJSON), filepath.Join(stage, "package.json"), 0o644); err != nil {
		return nil, err
	}
	if err := CopyFile(r.path(d.NPMLockfile), filepath.Join(stage, "package-lock.json"), 0o644); err != nil {
		return nil, err
	}
	npm := o.NPM
	if npm == "" {
		npm = "npm"
	}
	env := minimalEnv("npm_config_update_notifier=false")
	if o.Fetcher.NPMRegistry != "" {
		env = append(env, "npm_config_registry="+o.Fetcher.NPMRegistry)
	}
	if err := runTool(ctx, stage, env, o.Log, npm, "ci", "--omit=dev", "--ignore-scripts", "--no-bin-links", "--no-audit", "--no-fund"); err != nil {
		return nil, err
	}
	_ = os.RemoveAll(filepath.Join(stage, "node_modules", ".package-lock.json"))
	return &DependencyLock{Kind: "npm-lockfile", SHA256: SHA256Hex(lockRaw)}, nil
}

// stagePyPI installs the distribution under site/. With a requirements file
// (hashes required) pip installs the pinned closure from wheels only;
// without one the wheel itself is unpacked.
func (r *Recipe) stagePyPI(ctx context.Context, fe *Fetched, stage string, o BuildOptions) (*DependencyLock, error) {
	site := filepath.Join(stage, "site")
	d := r.Dependencies
	if d == nil || d.PipRequirements == "" {
		if !strings.HasSuffix(fe.FileName, ".whl") {
			return nil, errors.New("without dependencies.pip_requirements the pinned PyPI file must be a wheel")
		}
		return nil, extractZip(fe.Path, site)
	}
	req, err := os.ReadFile(r.path(d.PipRequirements))
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(req, []byte("--hash=sha256:"+r.Artifact.SHA256)) {
		return nil, Errf(ReasonDigestMismatch, "the requirements file does not pin %s with --hash=sha256:%s", r.Artifact.Name, r.Artifact.SHA256)
	}
	py := o.Python
	if py == "" {
		py = "python3"
	}
	env := minimalEnv("PIP_DISABLE_PIP_VERSION_CHECK=1", "PYTHONDONTWRITEBYTECODE=1")
	if o.Fetcher.PyPIIndex != "" {
		env = append(env, "PIP_INDEX_URL="+strings.TrimSuffix(o.Fetcher.PyPIIndex, "/")+"/simple")
	}
	if err := runTool(ctx, stage, env, o.Log, py, "-m", "pip", "install", "--no-deps", "--require-hashes", "--only-binary=:all:", "--no-compile",
		"--target", site, "-r", r.path(d.PipRequirements)); err != nil {
		return nil, err
	}
	// pip writes console scripts with an absolute interpreter path; they
	// are not used (launch runs python -m), so drop them for a stable tree.
	_ = os.RemoveAll(filepath.Join(site, "bin"))
	return &DependencyLock{Kind: "pip-requirements", SHA256: SHA256Hex(req)}, nil
}

// extractZip unpacks a wheel into dest with the same rules as ExtractTarGz.
func extractZip(archive, dest string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(zr.File))
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		names = append(names, f.Name)
		files[f.Name] = f
	}
	sort.Strings(names)
	var total uint64
	for i, n := range names {
		if i > maxArchiveFiles {
			return errors.New("archive exceeds the unpacking bounds")
		}
		zf := files[n]
		rel, ok, err := cleanArchivePath(n, "")
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if !zf.FileInfo().Mode().IsRegular() {
			return fmt.Errorf("entry %q: links and special files are not allowed", n)
		}
		total += zf.UncompressedSize64
		if total > maxArchiveBytes {
			return errors.New("archive exceeds the unpacking bounds")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) //nolint:gosec // artifact content is public
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, int64(zf.UncompressedSize64)+1)) //nolint:gosec // bounded by maxArchiveBytes above
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func makeOwnerWritable(dir string) { MakeWritable(dir) }
