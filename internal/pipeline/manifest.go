package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolSet is the tool list of one server revision as the Gateway will
// present it. Verified is true only when the definitions come from a signed
// manifest checked by the Library Trust Verifier (E-13); Source names where
// they came from ("live" for the unverified default).
type ToolSet struct {
	Tools    []*mcp.Tool
	Revision string
	Verified bool
	Source   string
	// Withheld lists the tools of the revision that a source left out of
	// Tools because a check blocked them (the import-time metadata scan,
	// SR-5.9-2). The Local Server Registry records them as suspended.
	Withheld []WithheldTool
}

// WithheldTool is a tool of a server revision registered as suspended
// instead of presented.
type WithheldTool struct {
	Name       string    `json:"name"`
	ReasonCode string    `json:"reason_code"`
	Stage      string    `json:"stage"` // "import"
	Findings   []Finding `json:"findings"`
}

// LiveLister returns the server's complete live tool list (FR-5.21).
type LiveLister func(ctx context.Context) ([]*mcp.Tool, error)

// ManifestSource decides the tool definitions of a server (E-13, E-14). A
// verified implementation loads the signed manifest of the package, compares
// it with the live list (drift, FR-5.22) and returns the manifest's
// definitions (FR-1.27).
type ManifestSource interface {
	Tools(ctx context.Context, spec ServerSpec, live LiveLister) (ToolSet, error)
}

// ErrServerSuspended is returned (wrapped) by a ManifestSource or Launcher
// when a server revision has been suspended, for example on manifest drift
// (SR-3.8-1) or a changed artifact (SR-3-2). The registry starts without
// that server instead of failing startup.
var ErrServerSuspended = errors.New("server revision suspended")

// ManifestWatcher is optionally implemented by a ManifestSource. The
// registry calls ListChanged when a running server sends
// notifications/tools/list_changed; an error wrapping ErrServerSuspended
// suspends the server and tears its instance down (SR-3.8-1).
type ManifestWatcher interface {
	ListChanged(ctx context.Context, spec ServerSpec, live LiveLister) error
}

// LiveManifest is the default ManifestSource: it presents the live tool
// list, flagged as unverified. Its revision is "live-" and the first 16 hex
// digits of the SHA-256 of the sorted list.
type LiveManifest struct{}

// Tools implements ManifestSource.
func (LiveManifest) Tools(ctx context.Context, _ ServerSpec, live LiveLister) (ToolSet, error) {
	tools, err := live(ctx)
	if err != nil {
		return ToolSet{}, err
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	raw, err := json.Marshal(tools)
	if err != nil {
		return ToolSet{}, err
	}
	sum := sha256.Sum256(raw)
	return ToolSet{Tools: tools, Revision: "live-" + hex.EncodeToString(sum[:8]), Source: "live"}, nil
}

// SecretRequest asks the Secret Broker for the values of a launch's secret
// references. Refs maps environment variable names to secret references as
// written in the server configuration.
type SecretRequest struct {
	Server string
	Refs   map[string]string
}

// SecretBroker resolves secret references for a launch (E-20). The returned
// map holds environment variable values to inject; the Launcher must not log
// them. A broker records each secret use as evidence itself.
type SecretBroker interface {
	Resolve(ctx context.Context, req SecretRequest) (map[string]string, error)
}

// ErrNoSecretBroker is returned by NoSecrets when a server needs secrets.
var ErrNoSecretBroker = errors.New("server configuration names secrets but no secret broker is configured")

// NoSecrets is the default SecretBroker: it resolves nothing and refuses
// any request that names a secret, so a server that needs secrets does not
// start.
type NoSecrets struct{}

// Resolve implements SecretBroker.
func (NoSecrets) Resolve(_ context.Context, req SecretRequest) (map[string]string, error) {
	if len(req.Refs) > 0 {
		return nil, ErrNoSecretBroker
	}
	return nil, nil
}

// BaseEnv is the environment every server instance starts with: PATH and
// HOME of the Gateway process, so that ordinary executables run. Nothing
// else is inherited (SR-2.14-1).
func BaseEnv() map[string]string {
	return map[string]string{"PATH": os.Getenv("PATH"), "HOME": os.Getenv("HOME")}
}

// MergeEnv builds a launch environment: base, then configured values, then
// resolved secrets. A secret may not override a configured variable.
func MergeEnv(base, configured, secrets map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(base)+len(configured)+len(secrets))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range configured {
		out[k] = v
	}
	for k, v := range secrets {
		if _, dup := configured[k]; dup {
			return nil, fmt.Errorf("secret %s would override a configured variable", k)
		}
		out[k] = v
	}
	return out, nil
}
