package packaging

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Eras are the southbound protocol eras a manifest may declare (FR-5.16).
var Eras = []string{"2026-07-28", "2025-11-25"}

// ProbeEra is the protocol version the probe requests: the 2025-11-25
// handshake of the Gateway's dispatcher (FR-5.19). The 2026-07-28 probe
// of FR-5.16 is deferred (SRS Appendix N).
const ProbeEra = "2025-11-25"

// ProbeResult is what the packaging run observed.
type ProbeResult struct {
	Era   string
	Tools []*mcp.Tool
	Env   ProbeEnvironment
}

// ProbeOptions configure Probe.
type ProbeOptions struct {
	// Launcher runs the candidate. Default SubprocessLauncher (no
	// confinement, host network: the Standalone profile). A confining
	// launcher removes network access (SR-3.5-1 in the Enforced profile).
	Launcher pipeline.Launcher
	Timeout  time.Duration // default 60s
}

// Probe starts the candidate once with spec, performs the era negotiation
// and reads its complete tool list (FR-14.3). The environment is exactly
// spec.Env plus a minimal PATH; HOME is the working directory, which the
// caller makes an empty throwaway directory.
func Probe(ctx context.Context, spec pipeline.ServerSpec, o ProbeOptions) (*ProbeResult, error) {
	if o.Launcher == nil {
		o.Launcher = pipeline.SubprocessLauncher{TerminateAfter: 2 * time.Second}
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	env := map[string]string{}
	for k, v := range spec.Env {
		env[k] = v
	}
	if _, ok := env["PATH"]; !ok {
		env["PATH"] = DefaultPath
	}
	if _, ok := env["HOME"]; !ok {
		env["HOME"] = spec.Dir
	}
	spec.Env = env
	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)
	res := &ProbeResult{Env: ProbeEnvironment{Launcher: o.Launcher.Name(), Confined: o.Launcher.Confined(), Network: "host", EnvNames: names}}
	if o.Launcher.Confined() {
		res.Env.Network = "none"
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	proc, err := o.Launcher.Launch(ctx, spec)
	if err != nil {
		return nil, Wrap(ReasonProbeFailed, "start the candidate server", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "smcpctl-package", Version: "1"}, nil)
	// The probe uses the handshake the Gateway uses (FR-5.19): initialize
	// with 2025-11-25, so the recorded era is the one the Gateway will
	// negotiate (FR-5.40).
	sess, err := client.Connect(ctx, &mcp.IOTransport{Reader: proc, Writer: procWriteCloser{proc}}, &mcp.ClientSessionOptions{ProtocolVersion: ProbeEra})
	if err != nil {
		stderr := proc.Stderr()
		proc.Close()
		return nil, Wrap(ReasonProbeFailed, fmt.Sprintf("connect (stderr: %s)", truncate(stderr, 2000)), err)
	}
	defer sess.Close()
	if ir := sess.InitializeResult(); ir != nil {
		res.Era = ir.ProtocolVersion
	}
	if !slices.Contains(Eras, res.Era) {
		return nil, Errf(ReasonEraUnsupported, "the server negotiated protocol version %q; manifests support %v", res.Era, Eras)
	}
	for t, err := range sess.Tools(ctx, nil) {
		if err != nil {
			return nil, Wrap(ReasonProbeFailed, "tools/list", err)
		}
		res.Tools = append(res.Tools, t)
	}
	if len(res.Tools) == 0 {
		return nil, Errf(ReasonProbeFailed, "the server lists no tools")
	}
	return res, nil
}

type procWriteCloser struct{ p pipeline.Process }

func (w procWriteCloser) Write(b []byte) (int, error) { return w.p.Write(b) }
func (w procWriteCloser) Close() error                { return w.p.Close() }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ThrowawayDir creates an empty temporary directory for a probe.
func ThrowawayDir(prefix string) (string, func(), error) {
	d, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", nil, err
	}
	return d, func() { MakeWritable(d); os.RemoveAll(d) }, nil
}
