package packaging

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// manifestSchemaJSON is a copy of docs/schemas/manifest.schema.json
// (Appendix J); a test keeps the two identical.
//
//go:embed manifest.schema.json
var manifestSchemaJSON []byte

// ManifestVersion is the only manifest_version this release reads.
const ManifestVersion = 1

// Manifest is the Appendix J package manifest.
type Manifest struct {
	ManifestVersion int                `json:"manifest_version"`
	Server          ServerInfo         `json:"server"`
	Artifact        ArtifactInfo       `json:"artifact"`
	Launch          Launch             `json:"launch"`
	Era             string             `json:"era"`
	RiskClass       string             `json:"risk_class"`
	InstanceScope   []string           `json:"instance_scope"`
	Stateful        bool               `json:"stateful,omitempty"`
	Tools           []Tool             `json:"tools"`
	ToolsListSHA256 string             `json:"tools_list_sha256,omitempty"`
	Capabilities    Capabilities       `json:"capabilities"`
	Secrets         []SecretSlot       `json:"secrets,omitempty"`
	BehaviorHints   json.RawMessage    `json:"behavior_hints,omitempty"`
	Provenance      ManifestProvenance `json:"provenance"`
	Packaging       PackagingInfo      `json:"packaging"`
	Attestations    *Attestations      `json:"attestations,omitempty"`
	Expires         string             `json:"expires,omitempty"`
}

// ServerInfo identifies the server and revision.
type ServerInfo struct {
	ID          string `json:"id"`
	Revision    string `json:"revision"`
	Alias       string `json:"alias"`
	Publisher   string `json:"publisher"`
	Description string `json:"description,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
}

// ArtifactInfo pins the stored artifact.
type ArtifactInfo struct {
	Type              string `json:"type"`
	Reference         string `json:"reference"`
	Version           string `json:"version"`
	SHA256            string `json:"sha256"`
	RegistryIntegrity string `json:"registry_integrity,omitempty"`
	SizeBytes         int64  `json:"size_bytes,omitempty"`
}

// Launch is the exact argument vector, run without a shell.
type Launch struct {
	Runtime      string            `json:"runtime"`
	Argv         []string          `json:"argv"`
	EnvAllowlist []string          `json:"env_allowlist,omitempty"`
	EnvFixed     map[string]string `json:"env_fixed,omitempty"`
}

// Tool is one tool definition as read from the live tools/list at
// packaging, with the operator's classification.
type Tool struct {
	Name              string          `json:"name"`
	Title             string          `json:"title,omitempty"`
	Description       string          `json:"description,omitempty"`
	DescriptionSHA256 string          `json:"description_sha256"`
	InputSchema       json.RawMessage `json:"input_schema"`
	OutputSchema      json.RawMessage `json:"output_schema,omitempty"`
	Annotations       json.RawMessage `json:"annotations,omitempty"`
	SideEffect        string          `json:"side_effect"`
	SourceTrust       string          `json:"source_trust"`
	RiskClass         string          `json:"risk_class,omitempty"`
	// Class is "gateway-admin" for a tool that administers the Gateway;
	// such a tool is never presented (SR-3.12-1). "" is standard.
	Class string `json:"class,omitempty"`
}

// Capabilities is the capability ceiling.
type Capabilities struct {
	Filesystem      []FilesystemSlot `json:"filesystem"`
	Egress          []EgressRule     `json:"egress"`
	SpawnsProcesses bool             `json:"spawns_processes"`
	Resources       Resources        `json:"resources"`
}

// FilesystemSlot is a named mount point the policy binds a host path to.
type FilesystemSlot struct {
	Slot            string `json:"slot"`
	Mode            string `json:"mode"`
	ArgvPlaceholder string `json:"argv_placeholder,omitempty"`
}

// EgressRule is one permitted destination. The optional limits bound each
// outbound operation to it (FR-5.38); the Egress Broker applies the
// smallest of these, the configuration's and the decision's.
type EgressRule struct {
	Host          string   `json:"host"`
	Ports         []int    `json:"ports"`
	Methods       []string `json:"methods"`
	RequestBytes  int64    `json:"request_bytes,omitempty"`
	ResponseBytes int64    `json:"response_bytes,omitempty"`
	TimeoutMS     int64    `json:"timeout_ms,omitempty"`
}

// Resources are instance resource limits.
type Resources struct {
	MemoryMiB   int     `json:"memory_mib,omitempty"`
	CPUs        float64 `json:"cpus,omitempty"`
	Pids        int     `json:"pids,omitempty"`
	WallSeconds int     `json:"wall_seconds,omitempty"`
}

// SecretSlot names a secret the server needs.
type SecretSlot struct {
	Slot        string   `json:"slot"`
	Purpose     string   `json:"purpose"`
	Destination string   `json:"destination,omitempty"`
	Modes       []string `json:"modes"`
	EnvName     string   `json:"env_name,omitempty"`
}

// ManifestProvenance is the manifest's source and license evidence.
type ManifestProvenance struct {
	Source          Source   `json:"source"`
	Licenses        []string `json:"licenses"`
	StatementSHA256 string   `json:"statement_sha256"`
}

// Source is the source reference bound to the artifact.
type Source struct {
	Kind      string `json:"kind"`
	URI       string `json:"uri"`
	SHA256    string `json:"sha256"`
	VCSCommit string `json:"vcs_commit,omitempty"`
}

// PackagingInfo records how the package was built.
type PackagingInfo struct {
	Tool         string `json:"tool"`
	ToolVersion  string `json:"tool_version"`
	BuiltAt      string `json:"built_at"`
	OperatorNote string `json:"operator_note,omitempty"`
}

// Attestations are curation attestations.
type Attestations struct {
	ReviewStatus        string `json:"review_status,omitempty"`
	AdvisoriesCheckedAt string `json:"advisories_checked_at,omitempty"`
	RecurationDue       string `json:"recuration_due,omitempty"`
}

var manifestSchema = func() *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(manifestSchemaJSON))
	if err != nil {
		panic("embedded manifest schema: " + err.Error())
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("manifest.schema.json", doc); err != nil {
		panic(err)
	}
	s, err := c.Compile("manifest.schema.json")
	if err != nil {
		panic("compile manifest schema: " + err.Error())
	}
	return s
}()

// ManifestSchemaJSON returns the embedded Appendix J schema.
func ManifestSchemaJSON() []byte { return append([]byte(nil), manifestSchemaJSON...) }

var urlLike = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// ParseManifest checks the declared manifest_version, validates raw against
// the Appendix J schema (FR-14.11), decodes it and applies the rules the
// schema cannot express: a local entrypoint (FR-14.4), no package runner or
// shell (SR-3.6-1), the tool-list digest and description digests.
func ParseManifest(raw []byte) (*Manifest, error) {
	var head struct {
		ManifestVersion *json.Number `json:"manifest_version"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&head); err != nil {
		return nil, Wrap(ReasonManifestSchema, "manifest is not a JSON object", err)
	}
	if head.ManifestVersion == nil {
		return nil, Errf(ReasonManifestSchema, "manifest_version is missing")
	}
	if head.ManifestVersion.String() != "1" {
		return nil, Errf(ReasonManifestVersion, "manifest_version %s is not supported (this release reads version %d)", head.ManifestVersion.String(), ManifestVersion)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, Wrap(ReasonManifestSchema, "manifest is not JSON", err)
	}
	if err := manifestSchema.Validate(doc); err != nil {
		return nil, Wrap(ReasonManifestSchema, "manifest does not conform to docs/schemas/manifest.schema.json", err)
	}
	var m Manifest
	sd := json.NewDecoder(bytes.NewReader(raw))
	sd.DisallowUnknownFields()
	if err := sd.Decode(&m); err != nil {
		return nil, Wrap(ReasonManifestSchema, "decode manifest", err)
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	return &m, nil
}

// launchRefused are argv[0] base names that resolve or install packages at
// run time, or are shells (SR-3.6-1). The schema refuses the same set.
var launchRefused = []string{"npx", "uvx", "uv", "pip", "pip3", "pipx", "npm", "pnpm", "pnpx", "yarn", "bunx", "bun", "sh", "bash", "zsh", "dash", "curl", "wget", "deno", "poetry"}

// CheckArgv applies FR-14.4 and SR-3.6-1 to a launch vector.
func CheckArgv(runtime string, argv []string) error {
	if len(argv) == 0 {
		return Errf(ReasonUnpinnedLaunch, "launch argv is empty")
	}
	if urlLike.MatchString(argv[0]) {
		return Errf(ReasonRemoteBackend, "the server entrypoint %q is a URL, not a local executable or image", argv[0])
	}
	base := strings.ToLower(argv[0])
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".exe")
	if slices.Contains(launchRefused, base) {
		return Errf(ReasonUnpinnedLaunch, "%s resolves or installs packages at run time or is a shell", base)
	}
	for i, a := range argv {
		if a == "-m" && i+1 < len(argv) && slices.Contains([]string{"pip", "pipx", "uv", "ensurepip"}, argv[i+1]) {
			return Errf(ReasonUnpinnedLaunch, "-m %s installs packages", argv[i+1])
		}
	}
	switch runtime {
	case "native":
		if strings.HasPrefix(argv[0], "/") || strings.Contains(argv[0], "..") {
			return Errf(ReasonUnpinnedLaunch, "native argv[0] %q must be a path inside the artifact", argv[0])
		}
	case "node":
		if base != "node" {
			return Errf(ReasonUnpinnedLaunch, "node runtime argv[0] must be node, not %q", argv[0])
		}
	case "python":
		if !strings.HasPrefix(base, "python") {
			return Errf(ReasonUnpinnedLaunch, "python runtime argv[0] must be python or python3, not %q", argv[0])
		}
	}
	return nil
}

func (m *Manifest) check() error {
	if err := CheckArgv(m.Launch.Runtime, m.Launch.Argv); err != nil {
		return err
	}
	want := map[string]bool{"npm": m.Launch.Runtime == "node", "pypi": m.Launch.Runtime == "python", "oci": m.Launch.Runtime == "oci", "binary": m.Launch.Runtime == "native"}
	if !want[m.Artifact.Type] {
		return Errf(ReasonManifestSchema, "artifact type %s cannot run with runtime %s", m.Artifact.Type, m.Launch.Runtime)
	}
	seen := map[string]bool{}
	for _, t := range m.Tools {
		if seen[t.Name] {
			return Errf(ReasonManifestSchema, "tool %q is listed twice", t.Name)
		}
		seen[t.Name] = true
		if t.DescriptionSHA256 != SHA256Hex([]byte(t.Description)) {
			return Errf(ReasonManifestSchema, "tool %q: description_sha256 does not match its description", t.Name)
		}
		if t.RiskClass != "" && riskRank(t.RiskClass) < riskRank(m.RiskClass) {
			return Errf(ReasonManifestSchema, "tool %q: a per-tool risk class may only raise the server risk class", t.Name)
		}
	}
	if m.ToolsListSHA256 != "" {
		d, err := ToolsDigest(m.CanonicalTools())
		if err != nil {
			return Wrap(ReasonManifestSchema, "tools", err)
		}
		if d != m.ToolsListSHA256 {
			return Errf(ReasonManifestSchema, "tools_list_sha256 does not match the listed tools")
		}
	}
	placeholders := map[string]bool{}
	for _, f := range m.Capabilities.Filesystem {
		if f.ArgvPlaceholder != "" {
			placeholders[f.ArgvPlaceholder] = true
		}
	}
	for _, a := range append(append([]string(nil), m.Launch.Argv...), mapValues(m.Launch.EnvFixed)...) {
		for _, ph := range placeholderRE.FindAllString(a, -1) {
			if !placeholders[ph] {
				return Errf(ReasonManifestSchema, "launch uses placeholder %s that no filesystem slot declares", ph)
			}
		}
	}
	return nil
}

var placeholderRE = regexp.MustCompile(`\{[a-z][a-z0-9_]{0,31}\}`)

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// HighestRisk is the highest of the server and per-tool risk classes.
func (m *Manifest) HighestRisk() string {
	r := m.RiskClass
	for _, t := range m.Tools {
		if riskRank(t.RiskClass) > riskRank(r) {
			r = t.RiskClass
		}
	}
	return r
}

func riskRank(c string) int {
	switch c {
	case "low":
		return 1
	case "moderate":
		return 2
	case "high":
		return 3
	}
	return 0
}

// RiskClasses are the manifest risk classes in ascending order.
var RiskClasses = []string{"low", "moderate", "high"}

// SHA256Hex returns the lowercase hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// CanonicalTool is the comparable form of one tool: the members of a
// tools/list entry that drift detection covers (SR-3.8-1): name, title,
// description, input and output schema and annotations. Values are
// normalized JSON.
type CanonicalTool map[string]any

// canonical normalizes v to the generic JSON value form (sorted keys on
// marshal), dropping nulls.
func canonical(raw json.RawMessage) (any, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func canonicalTool(name, title, desc string, in, out, ann json.RawMessage) (CanonicalTool, error) {
	ct := CanonicalTool{"name": name}
	if title != "" {
		ct["title"] = title
	}
	if desc != "" {
		ct["description"] = desc
	}
	for k, raw := range map[string]json.RawMessage{"inputSchema": in, "outputSchema": out, "annotations": ann} {
		v, err := canonical(raw)
		if err != nil {
			return nil, fmt.Errorf("tool %q %s: %w", name, k, err)
		}
		if v != nil {
			if m, ok := v.(map[string]any); ok && len(m) == 0 && k == "annotations" {
				continue
			}
			ct[k] = v
		}
	}
	return ct, nil
}

// CanonicalLive converts a live tools/list to canonical tools.
func CanonicalLive(tools []*mcp.Tool) ([]CanonicalTool, error) {
	out := make([]CanonicalTool, 0, len(tools))
	for _, t := range tools {
		in, err := json.Marshal(t.InputSchema)
		if err != nil {
			return nil, err
		}
		var outS, ann json.RawMessage
		if t.OutputSchema != nil {
			if outS, err = json.Marshal(t.OutputSchema); err != nil {
				return nil, err
			}
		}
		if t.Annotations != nil {
			if ann, err = json.Marshal(t.Annotations); err != nil {
				return nil, err
			}
		}
		ct, err := canonicalTool(t.Name, t.Title, t.Description, in, outS, ann)
		if err != nil {
			return nil, err
		}
		out = append(out, ct)
	}
	sortTools(out)
	return out, nil
}

// CanonicalTools returns the manifest's tools in canonical form.
func (m *Manifest) CanonicalTools() []CanonicalTool {
	out := make([]CanonicalTool, 0, len(m.Tools))
	for _, t := range m.Tools {
		ct, err := canonicalTool(t.Name, t.Title, t.Description, t.InputSchema, t.OutputSchema, t.Annotations)
		if err != nil {
			// ParseManifest validated the members as JSON; keep the name so
			// a comparison still reports the tool as different.
			ct = CanonicalTool{"name": t.Name, "invalid": err.Error()}
		}
		out = append(out, ct)
	}
	sortTools(out)
	return out
}

func sortTools(ts []CanonicalTool) {
	sort.Slice(ts, func(i, j int) bool { return ts[i]["name"].(string) < ts[j]["name"].(string) })
}

// ToolsDigest is the SHA-256 of the canonical JSON of a sorted tool list
// (tools_list_sha256, SR-3.7-1).
func ToolsDigest(ts []CanonicalTool) (string, error) {
	raw, err := json.Marshal(ts)
	if err != nil {
		return "", err
	}
	return SHA256Hex(raw), nil
}

// Drift compares a manifest's tools with a live list and returns a
// human-readable difference per tool name; nil means identical.
func Drift(manifest, live []CanonicalTool) []string {
	idx := func(ts []CanonicalTool) map[string][]byte {
		m := map[string][]byte{}
		for _, t := range ts {
			raw, _ := json.Marshal(t)
			m[t["name"].(string)] = raw
		}
		return m
	}
	want, got := idx(manifest), idx(live)
	var diffs []string
	for name, w := range want {
		g, ok := got[name]
		switch {
		case !ok:
			diffs = append(diffs, name+": missing from the live list")
		case !bytes.Equal(w, g):
			diffs = append(diffs, name+": definition differs ("+differingMembers(w, g)+")")
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			diffs = append(diffs, name+": not in the manifest")
		}
	}
	sort.Strings(diffs)
	return diffs
}

func differingMembers(a, b []byte) string {
	var ma, mb map[string]json.RawMessage
	_ = json.Unmarshal(a, &ma)
	_ = json.Unmarshal(b, &mb)
	var out []string
	for _, k := range []string{"title", "description", "inputSchema", "outputSchema", "annotations"} {
		if !bytes.Equal(ma[k], mb[k]) {
			out = append(out, k)
		}
	}
	return strings.Join(out, ", ")
}

// MCPTools converts the manifest's tools to the definitions the Gateway
// presents (FR-1.27).
func (m *Manifest) MCPTools() ([]*mcp.Tool, error) {
	out := make([]*mcp.Tool, 0, len(m.Tools))
	for _, ct := range m.CanonicalTools() {
		raw, err := json.Marshal(ct)
		if err != nil {
			return nil, err
		}
		var t mcp.Tool
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("tool %v: %w", ct["name"], err)
		}
		if t.InputSchema == nil {
			t.InputSchema = map[string]any{"type": "object"}
		}
		// The manifest's classes reach the decision through the tool's
		// metadata (SR-1.18-1, SR-5.13-2, SR-3.12-1); the edge reads them
		// only from verified manifests.
		if mt := m.Find(t.Name); mt != nil {
			t.Meta = mcp.Meta{policy.MetaSideEffect: mt.SideEffect, policy.MetaSourceTrust: mt.SourceTrust}
			if mt.Class != "" {
				t.Meta[policy.MetaToolClass] = mt.Class
			}
		}
		out = append(out, &t)
	}
	return out, nil
}

// Find returns the manifest tool with the given name.
func (m *Manifest) Find(name string) *Tool {
	for i := range m.Tools {
		if m.Tools[i].Name == name {
			return &m.Tools[i]
		}
	}
	return nil
}
