package adapter

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// UDS relay (FR-12.13 with the UDS Harness Profile, FR-1.47, FR-2.15).
// When the credential file names [gateway] socket, smcp-stdio connects to
// the Gateway's UDS harness socket, which already speaks newline-delimited
// JSON-RPC: it authenticates once with the peer's bearer key
// ([gateway] uds_key) and then copies lines unchanged in both directions.
// The Gateway checks the kernel-reported UID of this process and the key;
// the session lasts as long as the connection.

// methodUDSAuthenticate is the first message on the socket
// (edge.MethodUDSAuthenticate).
const methodUDSAuthenticate = "local.smcpgw/authenticate"

// maxUDSLine bounds one message on the socket.
const maxUDSLine = 16 << 20

// RunUDS relays in and out over the socket until in ends, the socket
// closes or ctx is cancelled.
func RunUDS(ctx context.Context, socket, key string, in io.Reader, out io.Writer) error {
	if key == "" {
		return errors.New("[gateway] uds_key is not set")
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("gateway socket: %w", err)
	}
	defer c.Close()
	auth, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 0, "method": methodUDSAuthenticate, "params": map[string]string{"key": key}})
	if _, err := c.Write(append(auth, '\n')); err != nil {
		return fmt.Errorf("gateway socket: %w", err)
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64<<10), maxUDSLine)
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	if !sc.Scan() {
		err := sc.Err()
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("gateway socket closed during authentication: %w", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	var reply struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(sc.Bytes(), &reply); err != nil {
		return fmt.Errorf("gateway socket: authentication reply: %w", err)
	}
	if reply.Error != nil {
		return fmt.Errorf("the Gateway refused the socket session (%d %s): check [gateway] uds_key and the [[uds.peer]] entry for this user", reply.Error.Code, reply.Error.Message)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	// Requests sent and not yet answered: when standard input ends, the
	// relay waits for their replies before closing, because closing the
	// socket cancels them at the Gateway.
	var mu sync.Mutex
	pending := map[string]bool{}
	drained := make(chan struct{}, 1)
	idOf := func(line []byte) (string, bool) {
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(line, &m) != nil || len(m.ID) == 0 || string(m.ID) == "null" {
			return "", false
		}
		return string(m.ID), true
	}
	up := make(chan error, 1)
	go func() {
		in := bufio.NewScanner(in)
		in.Buffer(make([]byte, 0, 64<<10), maxUDSLine)
		for in.Scan() {
			line := in.Bytes()
			if len(line) == 0 {
				continue
			}
			if id, ok := idOf(line); ok {
				mu.Lock()
				pending[id] = true
				mu.Unlock()
			}
			if _, err := c.Write(append(append([]byte(nil), line...), '\n')); err != nil {
				up <- err
				return
			}
		}
		up <- in.Err()
	}()
	down := make(chan error, 1)
	go func() {
		for sc.Scan() {
			line := sc.Bytes()
			if _, err := out.Write(append(append([]byte(nil), line...), '\n')); err != nil {
				down <- err
				return
			}
			if id, ok := idOf(line); ok {
				mu.Lock()
				delete(pending, id)
				empty := len(pending) == 0
				mu.Unlock()
				if empty {
					select {
					case drained <- struct{}{}:
					default:
					}
				}
			}
		}
		down <- sc.Err()
	}()
	select {
	case err := <-up:
		if err != nil {
			return err
		}
		// Standard input ended: wait for the replies in flight.
		for {
			mu.Lock()
			empty := len(pending) == 0
			mu.Unlock()
			if empty {
				return nil
			}
			select {
			case <-drained:
			case <-down:
				return nil
			case <-time.After(60 * time.Second):
				return errors.New("no reply from the Gateway within 60 seconds after input ended")
			case <-ctx.Done():
				return nil
			}
		}
	case err := <-down:
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return errors.New("the Gateway closed the socket")
		}
		return err
	}
}
