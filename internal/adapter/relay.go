package adapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
)

// MaxMessageBytes bounds one newline-delimited message on standard input.
const MaxMessageBytes = 16 << 20

// metaProtocolVersion is the 2026-07-28 per-request version key.
const metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"

// Relay forwards newline-delimited JSON-RPC messages between a stdio MCP
// client (the framework) and the Gateway's Streamable HTTP endpoint. Each
// message is sent unchanged as one POST with the session credential; the
// framework's protocol era is preserved by deriving the MCP headers from
// the message itself: Mcp-Protocol-Version from the message's _meta
// version (2026-07-28 era) or from the version the initialize result
// negotiated (2025-11-25 era), and Mcp-Method and Mcp-Name from the body.
type Relay struct {
	URL    string
	HTTP   *http.Client
	Tokens TokenSource
	In     io.Reader
	Out    io.Writer
	Log    *slog.Logger

	outMu      sync.Mutex
	mu         sync.Mutex
	negotiated string // legacy-era protocol version from initialize
	sessionID  string // Mcp-Session-Id, when a server issues one
	wg         sync.WaitGroup
}

type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name string         `json:"name"`
		URI  string         `json:"uri"`
		Meta map[string]any `json:"_meta"`
	} `json:"params"`
}

// Run relays until standard input ends or ctx is cancelled, then waits for
// requests in flight.
func (r *Relay) Run(ctx context.Context) error {
	if r.Log == nil {
		r.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	rd := bufio.NewReaderSize(r.In, 64<<10)
	var readErr error
	for {
		line, err := readLine(rd)
		if len(bytes.TrimSpace(line)) > 0 {
			msg := append([]byte(nil), bytes.TrimSpace(line)...)
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.forward(ctx, msg)
			}()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	r.wg.Wait()
	return readErr
}

func readLine(rd *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := rd.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > MaxMessageBytes {
			// Drain the rest of the line and report it.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = rd.ReadSlice('\n')
			}
			return nil, fmt.Errorf("message longer than %d bytes", MaxMessageBytes)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return buf, err
	}
}

func (r *Relay) write(msg []byte) {
	msg = bytes.TrimSpace(msg)
	if len(msg) == 0 {
		return
	}
	if bytes.ContainsAny(msg, "\r\n") {
		var c bytes.Buffer
		if json.Compact(&c, msg) == nil {
			msg = c.Bytes()
		}
	}
	r.outMu.Lock()
	defer r.outMu.Unlock()
	_, _ = r.Out.Write(append(msg, '\n'))
}

// writeError answers a request the relay could not deliver.
func (r *Relay) writeError(id json.RawMessage, code int, msg string) {
	if len(id) == 0 || string(id) == "null" {
		return
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
	r.write(b)
}

func (r *Relay) protocolVersion(env envelope) string {
	if v, ok := env.Params.Meta[metaProtocolVersion].(string); ok && v != "" {
		return v
	}
	if env.Method == "initialize" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.negotiated
}

func (r *Relay) forward(ctx context.Context, msg []byte) {
	var env envelope
	if err := json.Unmarshal(msg, &env); err != nil {
		// Forward anyway: the Gateway answers malformed input itself.
		r.Log.Debug("relaying a message that is not a JSON-RPC object")
	}
	for attempt := 0; attempt < 2; attempt++ {
		status, err := r.post(ctx, msg, env)
		if err != nil {
			r.Log.Warn("gateway request failed", "method", env.Method, "err", err)
			r.writeError(env.ID, -32000, "smcp adapter: "+err.Error())
			return
		}
		if status != http.StatusUnauthorized {
			return
		}
		r.Tokens.Invalidate()
	}
	r.writeError(env.ID, -31006, "smcp adapter: the Gateway refused the session (HTTP 401) after a refresh; sign in again")
}

// post sends one message and relays the response. It returns the HTTP
// status and an error only when nothing was relayed.
func (r *Relay) post(ctx context.Context, msg []byte, env envelope) (int, error) {
	tok, err := r.Tokens.Token(ctx)
	if err != nil {
		return 0, fmt.Errorf("no Gateway session: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.URL, bytes.NewReader(msg))
	if err != nil {
		return 0, err
	}
	h := req.Header
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/event-stream")
	h.Set("Authorization", "Bearer "+tok)
	if v := r.protocolVersion(env); v != "" {
		h.Set("Mcp-Protocol-Version", v)
	}
	if env.Method != "" {
		h.Set("Mcp-Method", env.Method)
		switch env.Method {
		case "tools/call", "prompts/get":
			if env.Params.Name != "" {
				h.Set("Mcp-Name", env.Params.Name)
			}
		case "resources/read":
			if env.Params.URI != "" {
				h.Set("Mcp-Name", env.Params.URI)
			}
		}
	}
	r.mu.Lock()
	if r.sessionID != "" {
		h.Set("Mcp-Session-Id", r.sessionID)
	}
	r.mu.Unlock()
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		r.mu.Lock()
		r.sessionID = sid
		r.mu.Unlock()
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return resp.StatusCode, nil
	}
	if resp.StatusCode == http.StatusAccepted {
		return resp.StatusCode, nil
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mt {
	case "text/event-stream":
		return resp.StatusCode, r.relayStream(resp.Body, env)
	case "application/json":
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxMessageBytes))
		if err != nil {
			return resp.StatusCode, err
		}
		r.noteInitialize(env, b)
		if len(bytes.TrimSpace(b)) == 0 {
			return resp.StatusCode, fmt.Errorf("empty response (HTTP %d)", resp.StatusCode)
		}
		r.write(b)
		return resp.StatusCode, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp.StatusCode, fmt.Errorf("gateway answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
}

// noteInitialize records the negotiated legacy protocol version.
func (r *Relay) noteInitialize(env envelope, body []byte) {
	if env.Method != "initialize" {
		return
	}
	var res struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &res) == nil && res.Result.ProtocolVersion != "" {
		r.mu.Lock()
		r.negotiated = res.Result.ProtocolVersion
		r.mu.Unlock()
	}
}

// relayStream writes each event's data as one message.
func (r *Relay) relayStream(body io.Reader, env envelope) error {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), MaxMessageBytes)
	var data bytes.Buffer
	flush := func() {
		if data.Len() > 0 {
			r.noteInitialize(env, data.Bytes())
			r.write(data.Bytes())
			data.Reset()
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	return sc.Err()
}
