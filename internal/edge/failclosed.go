package edge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
)

// ServeFailClosed answers on the harness listener ln while the Gateway
// cannot start because its Evidence Journal cannot be opened for writing
// (FR-9.17): every request to the MCP endpoint gets HTTP 503 with Gateway
// error -31004 and reason code reason, and /healthz reports the state
// fail-closed. Nothing else is served and no session or tool is reached.
// Every interval it calls ready; when ready reports true it stops serving
// and returns nil, leaving ln open so that the Gateway can start on it.
// It returns ctx.Err() when ctx ends first.
func ServeFailClosed(ctx context.Context, cfg *config.Config, ln net.Listener, reason string, ready func() bool, interval time.Duration) error {
	certs, err := keys.NewCertReloader(cfg.Listener.TLSCert, cfg.Listener.TLSKey)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Listener.MCPPath, func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, cfg.Limits.RequestBodyBytes)).Decode(&msg)
		writeRPCErrorID(w, http.StatusServiceUnavailable, msg.ID,
			gatewayError(CodeGatewayFailClosed, "gateway fail-closed: evidence unavailable", reason, ids.New(), "", nil))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "fail-closed", "causes": []string{"journal"}})
	})
	keep := &keepOpen{Listener: ln}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: certs.GetCertificate}}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(tls.NewListener(keep, srv.TLSConfig)) }()
	t := time.NewTicker(interval)
	defer t.Stop()
	var result error
loop:
	for {
		select {
		case <-ctx.Done():
			result = ctx.Err()
			break loop
		case err := <-served:
			return err
		case <-t.C:
			if ready() {
				break loop
			}
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	keep.reopen()
	return result
}

// keepOpen is a listener that the fail-closed server can stop accepting
// on without closing it: Close makes a pending Accept return through a
// deadline in the past, and reopen clears the deadline for the next user.
type keepOpen struct {
	net.Listener
	mu     sync.Mutex
	closed bool
}

type deadliner interface{ SetDeadline(time.Time) error }

func (k *keepOpen) Accept() (net.Conn, error) {
	k.mu.Lock()
	closed := k.closed
	k.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	c, err := k.Listener.Accept()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		if c != nil {
			c.Close()
		}
		return nil, net.ErrClosed
	}
	return c, err
}

func (k *keepOpen) Close() error {
	k.mu.Lock()
	k.closed = true
	k.mu.Unlock()
	if d, ok := k.Listener.(deadliner); ok {
		return d.SetDeadline(time.Now())
	}
	return nil
}

func (k *keepOpen) reopen() {
	if d, ok := k.Listener.(deadliner); ok {
		_ = d.SetDeadline(time.Time{})
	}
}
