package secrets

import (
	"context"
	"sync"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// WrapLauncher returns a Launcher that delegates to inner and tears down
// the broker's deliveries for an instance when its process closes or fails
// to start (FR-6.8). Name and Confined are inner's, so the profile
// decision is unchanged. When inner is pipeline.EgressAware (the confining
// launcher of E-16), the wrapper is too and forwards SetEgress, so the
// Egress Broker still hands its attacher to the sandbox launcher.
func (b *Broker) WrapLauncher(inner pipeline.Launcher) pipeline.Launcher {
	if inner == nil {
		inner = pipeline.SubprocessLauncher{}
	}
	l := &launcher{inner: inner, b: b}
	if ea, ok := inner.(pipeline.EgressAware); ok {
		return &egressAwareLauncher{launcher: l, ea: ea}
	}
	return l
}

// egressAwareLauncher is a launcher whose inner launcher attaches egress
// itself.
type egressAwareLauncher struct {
	*launcher
	ea pipeline.EgressAware
}

func (l *egressAwareLauncher) SetEgress(a pipeline.EgressAttacher) { l.ea.SetEgress(a) }

type launcher struct {
	inner pipeline.Launcher
	b     *Broker
}

func (l *launcher) Name() string   { return l.inner.Name() }
func (l *launcher) Confined() bool { return l.inner.Confined() }

func (l *launcher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	p, err := l.inner.Launch(ctx, spec)
	if err != nil {
		l.b.Teardown(spec.Alias, "launch_failed")
		return nil, err
	}
	return &process{Process: p, done: func() { l.b.Teardown(spec.Alias, "instance_closed") }}, nil
}

type process struct {
	pipeline.Process
	once sync.Once
	done func()
}

// Unwrap implements pipeline.ProcessUnwrapper, so that the Tool
// Dispatcher reaches the egress capabilities of the wrapped process.
func (p *process) Unwrap() pipeline.Process { return p.Process }

func (p *process) Close() error {
	err := p.Process.Close()
	p.once.Do(p.done)
	return err
}
