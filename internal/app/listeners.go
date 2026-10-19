package app

import (
	"fmt"
	"net"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/edge"
	"github.com/ethan03805/secure-mcp-gateway/internal/metrics"
)

// Listeners are the configured TCP listeners of the daemon, bound before
// anything else opens a socket. Starting the Gateway opens listeners on
// port 0 (the egress proxy and endpoint listeners of each server instance),
// and the kernel may hand one of them a configured port that is free at
// that moment; binding the configured ports first means a daemon either
// gets its own ports or fails at once with a clear error.
type Listeners struct {
	Harness net.Listener
	Admin   net.Listener
	Metrics net.Listener // nil unless [metrics] enabled = true
}

// BindListeners binds the harness, admin and (when enabled) metrics
// listeners of cfg. On error nothing stays bound.
func BindListeners(cfg *config.Config) (*Listeners, error) {
	l := &Listeners{}
	fail := func(err error) (*Listeners, error) {
		l.Close()
		return nil, err
	}
	var err error
	if err = edge.CheckLoopback(cfg.Listener.Address); err != nil {
		return fail(err)
	}
	if l.Harness, err = net.Listen("tcp", cfg.Listener.Address); err != nil {
		return fail(fmt.Errorf("harness listener: %w", err))
	}
	if err = edge.CheckLoopback(cfg.AdminListener.Address); err != nil {
		return fail(err)
	}
	if l.Admin, err = net.Listen("tcp", cfg.AdminListener.Address); err != nil {
		return fail(fmt.Errorf("admin listener: %w", err))
	}
	if cfg.Metrics.Enabled {
		if l.Metrics, err = metrics.Listen(cfg.Metrics.Address); err != nil {
			return fail(fmt.Errorf("metrics: %w", err))
		}
	}
	return l, nil
}

// Close closes the listeners that are still open (the ones nothing
// served, after an error at start).
func (l *Listeners) Close() {
	if l == nil {
		return
	}
	for _, ln := range []net.Listener{l.Harness, l.Admin, l.Metrics} {
		if ln != nil {
			_ = ln.Close()
		}
	}
}
