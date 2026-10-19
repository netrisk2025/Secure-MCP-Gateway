package secrets

import (
	"context"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

type egressAwareFake struct {
	pipeline.SubprocessLauncher
	got pipeline.EgressAttacher
}

func (f *egressAwareFake) SetEgress(a pipeline.EgressAttacher) { f.got = a }

type attacherFake struct{}

func (attacherFake) Attach(context.Context, pipeline.EgressRequest) (*pipeline.EgressAttachment, error) {
	return &pipeline.EgressAttachment{}, nil
}

// The wrapper must keep an EgressAware inner launcher reachable, or the
// Egress Broker would wrap the confining launcher as an unconfined one.
func TestWrapLauncherForwardsEgressAware(t *testing.T) {
	b := &Broker{}
	inner := &egressAwareFake{}
	w := b.WrapLauncher(inner)
	ea, ok := w.(pipeline.EgressAware)
	if !ok {
		t.Fatal("wrapper of an EgressAware launcher is not EgressAware")
	}
	ea.SetEgress(attacherFake{})
	if inner.got == nil {
		t.Fatal("SetEgress was not forwarded")
	}
	if w.Name() != inner.Name() || w.Confined() != inner.Confined() {
		t.Fatal("Name/Confined not delegated")
	}
	if _, ok := b.WrapLauncher(pipeline.SubprocessLauncher{}).(pipeline.EgressAware); ok {
		t.Fatal("wrapper of a plain launcher claims EgressAware")
	}
}
