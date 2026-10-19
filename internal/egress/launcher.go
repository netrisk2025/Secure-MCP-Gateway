package egress

import (
	"context"
	"errors"
	"maps"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Wrap connects a launcher to the broker. A launcher that implements
// pipeline.EgressAware (the confining launcher of E-16) receives the broker
// and attaches its own sandbox networks. Any other launcher is wrapped so
// that each instance is attached without a network before it starts and
// detached after it exits: the instance gets the proxy and endpoint
// variables, which it may ignore (standalone profile, advisory). A nil
// broker returns the launcher unchanged.
func (b *Broker) Wrap(l pipeline.Launcher) pipeline.Launcher {
	if b == nil {
		return l
	}
	if ea, ok := l.(pipeline.EgressAware); ok {
		ea.SetEgress(b)
		return l
	}
	return &attachingLauncher{inner: l, att: b}
}

type attachingLauncher struct {
	inner pipeline.Launcher
	att   pipeline.EgressAttacher
}

func (l *attachingLauncher) Name() string   { return l.inner.Name() }
func (l *attachingLauncher) Confined() bool { return l.inner.Confined() }

// Launch attaches the instance, adds the attachment's variables to the
// environment (they replace configured variables of the same name) and
// starts the instance.
func (l *attachingLauncher) Launch(ctx context.Context, spec pipeline.ServerSpec) (pipeline.Process, error) {
	att, err := l.att.Attach(ctx, pipeline.EgressRequest{Alias: spec.Alias})
	if err != nil {
		return nil, err
	}
	env := maps.Clone(spec.Env)
	if env == nil {
		env = map[string]string{}
	}
	maps.Copy(env, att.Env)
	spec.Env = env
	p, err := l.inner.Launch(ctx, spec)
	if err != nil {
		return nil, errors.Join(err, att.Close())
	}
	return &attachedProcess{Process: p, detach: att.Close, issue: att.Issue}, nil
}

type attachedProcess struct {
	pipeline.Process
	detach func() error
	issue  func(pipeline.Binding) (*pipeline.EgressAuth, func())
}

// IssueEgress implements pipeline.EgressIssuer (SR-5.16-1).
func (p *attachedProcess) IssueEgress(b pipeline.Binding) (*pipeline.EgressAuth, func()) {
	if p.issue == nil {
		return nil, func() {}
	}
	return p.issue(b)
}

// Unwrap implements pipeline.ProcessUnwrapper.
func (p *attachedProcess) Unwrap() pipeline.Process { return p.Process }

func (p *attachedProcess) Close() error {
	return errors.Join(p.Process.Close(), p.detach())
}
