package app

import (
	"fmt"
	"net"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

func listenerConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Listener.Address = fmt.Sprintf("127.0.0.1:%d", testport.Free(t))
	cfg.AdminListener.Address = fmt.Sprintf("127.0.0.1:%d", testport.Free(t))
	cfg.Metrics.Enabled = true
	cfg.Metrics.Address = fmt.Sprintf("127.0.0.1:%d", testport.Free(t))
	return cfg
}

// TestBindListenersBindsConfiguredPorts: smcpd binds its configured
// listeners before the Gateway starts, and App.Listen then uses them.
func TestBindListenersBindsConfiguredPorts(t *testing.T) {
	cfg := listenerConfig(t)
	l, err := BindListeners(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for name, c := range map[string]struct {
		ln   net.Listener
		addr string
	}{"harness": {l.Harness, cfg.Listener.Address}, "admin": {l.Admin, cfg.AdminListener.Address}, "metrics": {l.Metrics, cfg.Metrics.Address}} {
		if c.ln == nil || c.ln.Addr().String() != c.addr {
			t.Fatalf("%s listener: %v, want %s", name, c.ln, c.addr)
		}
		if ln, err := net.Listen("tcp", c.addr); err == nil {
			ln.Close()
			t.Fatalf("%s port is not held", name)
		}
	}
	a := &App{Config: cfg, prebound: l}
	if err := a.Listen(); err != nil {
		t.Fatal(err)
	}
	if a.harnessLn != l.Harness || a.adminLn != l.Admin {
		t.Fatal("Listen bound new listeners instead of the bound ones")
	}
}

// TestBindListenersFailsWholly: when one configured port is taken, the
// daemon fails at start and releases the ports it had bound.
func TestBindListenersFailsWholly(t *testing.T) {
	cfg := listenerConfig(t)
	busy, err := net.Listen("tcp", cfg.Metrics.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if l, err := BindListeners(cfg); err == nil {
		l.Close()
		t.Fatal("bound with the metrics port taken")
	}
	for _, addr := range []string{cfg.Listener.Address, cfg.AdminListener.Address} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("%s still held after the failure: %v", addr, err)
		}
		ln.Close()
	}
	cfg.Metrics.Enabled = false
	cfg.AdminListener.Address = "192.0.2.1:8444"
	if l, err := BindListeners(cfg); err == nil {
		l.Close()
		t.Fatal("bound a non-loopback admin address")
	}
}
