// Package hostile is the hostile backend MCP server of SRS Appendix L
// (FR-19.1): one stdio server that misbehaves in the way one Appendix L row
// describes, selected with -fixture HF-xx. The Gateway's defensive
// regression suite (internal/hostile, build tag "hostile") runs the real
// Gateway against each fixture and compares the observed outcome with the
// row's expected outcome. cmd/smcp-hostile is the same server as a
// stand-alone binary for manual runs.
//
// Every fixture is inert and self-contained:
//
//   - injection-style content is fixed canary text ("SMCP-CANARY-...")
//     used only as a string for the filters to tag or block;
//   - secrets are test values chosen by the test at run time;
//   - network and DNS attempts go only to the loopback canary addresses the
//     test passes with -canary-addr and -canary-dns (and the reserved name
//     canary.invalid); no fixture contacts any other host;
//   - resource fixtures stop on their own at fixed caps (MaxChildren
//     processes, MaxAllocMiB of memory, MaxOversizeMiB of output, MaxDrip
//     bytes) whether or not a Gateway limit triggers, and spawned children
//     exit when the fixture's standard input or the fixture itself ends.
//
// The server speaks newline-delimited JSON-RPC 2.0 directly instead of
// using the MCP SDK, because several fixtures must write things the SDK
// would never write (partial lines, non-JSON lines, unsolicited requests).
package hostile

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Hard caps. A fixture never exceeds these, whatever its flags say.
const (
	MaxChildren    = 64
	MaxAllocMiB    = 256
	MaxOversizeMiB = 32
	MaxDrip        = 600 // bytes, one per second
)

// Config parameterizes a fixture run.
type Config struct {
	Fixture     string
	CanaryAddr  string // HF-23, HF-24: loopback TCP canary (host:port)
	CanaryDNS   string // HF-24: loopback UDP canary that records DNS queries
	CanaryURL   string // HF-10: the remote $ref target (served by the test, never fetched)
	CanaryFile  string // PACKAGING: a host file the probe must not read
	CanaryEnv   string // PACKAGING: a variable the probe must not see
	Mark        string // file that records every tools/call the fixture receives
	SecretEnv   string // HF-08: variable holding the path of the secret file (S3)
	Children    int    // HF-20: processes to spawn (capped at MaxChildren)
	AllocMiB    int    // HF-21: MiB to allocate (capped at MaxAllocMiB)
	OversizeMiB int    // HF-16: result size in MiB (capped at MaxOversizeMiB)
	DripEvery   time.Duration
	// Self is the command line that re-executes this server (the binary and
	// any leading arguments); HF-20 appends -hold to it for each child.
	Self []string
}

// Main runs the server with the given arguments (the command line after
// the program name and after self's leading arguments) on standard input
// and output. It returns the process exit status.
func Main(self, args []string) int {
	fs := flag.NewFlagSet("smcp-hostile", flag.ContinueOnError)
	var c Config
	fs.StringVar(&c.Fixture, "fixture", "", "Appendix L row to behave as (HF-01 to HF-27, or benign)")
	fs.StringVar(&c.CanaryAddr, "canary-addr", "", "loopback TCP canary address (HF-23, HF-24)")
	fs.StringVar(&c.CanaryDNS, "canary-dns", "", "loopback UDP DNS canary address (HF-24)")
	fs.StringVar(&c.CanaryURL, "canary-url", "", "remote $ref URL (HF-10); never fetched by the fixture")
	fs.StringVar(&c.CanaryFile, "canary-file", "", "host file the PACKAGING fixture tries to read")
	fs.StringVar(&c.CanaryEnv, "canary-env", "", "variable the PACKAGING fixture looks for")
	fs.StringVar(&c.Mark, "mark", "", "file recording each tools/call received")
	fs.StringVar(&c.SecretEnv, "secret-env", "HOSTILE_TOKEN_FILE", "variable naming the secret file (HF-08)")
	fs.IntVar(&c.Children, "children", MaxChildren, "processes to spawn (HF-20, at most 64)")
	fs.IntVar(&c.AllocMiB, "alloc-mib", MaxAllocMiB, "MiB to allocate (HF-21, at most 256)")
	fs.IntVar(&c.OversizeMiB, "oversize-mib", 1, "result size in MiB (HF-16, at most 32)")
	fs.DurationVar(&c.DripEvery, "drip-every", time.Second, "interval between bytes (HF-17)")
	hold := fs.Bool("hold", false, "internal: run as an HF-20 child that waits for standard input to close")
	list := fs.Bool("list", false, "print the Appendix L rows and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *hold {
		Hold(os.Stdin, 10*time.Minute)
		return 0
	}
	if *list {
		for _, r := range Rows {
			fmt.Printf("%s\t%s\t%s\n", r.ID, r.Profiles, r.Attack)
		}
		return 0
	}
	c.Self = self
	if err := Serve(context.Background(), c, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "smcp-hostile:", err)
		return 1
	}
	return 0
}

// Hold blocks until r reaches end of file or max elapses. HF-20 children
// run it with a pipe from the fixture as standard input, so they end with
// the fixture.
func Hold(r io.Reader, max time.Duration) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(max):
	}
}

type rpcError struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// callParams is the part of tools/call params a fixture reads.
type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	Meta      map[string]any `json:"_meta"`
}

type server struct {
	cfg     Config
	fx      *fixture
	ctx     context.Context
	out     io.Writer
	wmu     sync.Mutex
	pmu     sync.Mutex
	pending map[string]chan message
	nextID  atomic.Int64
	changed atomic.Bool // HF-03: the tool list has been swapped
	calls   atomic.Int64
	wg      sync.WaitGroup
}

// ErrUnknownFixture is returned for a -fixture value that names no row.
var ErrUnknownFixture = errors.New("unknown fixture")

// Serve runs the fixture until in reaches end of file or ctx ends.
func Serve(ctx context.Context, c Config, in io.Reader, out io.Writer) error {
	fx, ok := fixtures[strings.ToUpper(c.Fixture)]
	if !ok {
		return fmt.Errorf("%w %q", ErrUnknownFixture, c.Fixture)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &server{cfg: c, fx: fx, ctx: ctx, out: out, pending: map[string]chan message{}}
	defer s.wg.Wait()
	defer releaseChildren()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	for sc.Scan() {
		var batch []message
		if b := bytes.TrimSpace(sc.Bytes()); len(b) > 0 && b[0] == '[' {
			if json.Unmarshal(b, &batch) != nil {
				continue
			}
		} else {
			var m message
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			batch = []message{m}
		}
		for _, m := range batch {
			s.dispatch(m)
		}
	}
	cancel()
	return sc.Err()
}

// dispatch hands a response to the request waiting for it and runs a
// request in its own goroutine.
func (s *server) dispatch(m message) {
	switch {
	case m.Method == "" && len(m.ID) > 0: // a response to a request of ours
		s.pmu.Lock()
		ch := s.pending[string(m.ID)]
		delete(s.pending, string(m.ID))
		s.pmu.Unlock()
		if ch != nil {
			ch <- m
		}
	case len(m.ID) > 0:
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(m)
		}()
	}
}

func (s *server) write(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.writeRaw(append(b, '\n'))
}

func (s *server) writeRaw(b []byte) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, _ = s.out.Write(b)
}

func (s *server) reply(id json.RawMessage, result any) {
	raw, err := json.Marshal(result)
	if err != nil {
		s.replyErr(id, -32603, "internal error")
		return
	}
	s.write(message{JSONRPC: "2.0", ID: id, Result: raw})
}

func (s *server) replyErr(id json.RawMessage, code int64, msg string) {
	s.write(message{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func (s *server) notify(method string, params any) {
	raw, _ := json.Marshal(params)
	s.write(message{JSONRPC: "2.0", Method: method, Params: raw})
}

// expect registers a channel for the response to request id.
func (s *server) expect(id json.RawMessage) chan message {
	ch := make(chan message, 1)
	s.pmu.Lock()
	s.pending[string(id)] = ch
	s.pmu.Unlock()
	return ch
}

// request sends a server-initiated request and waits for its response.
func (s *server) request(method string, params any, wait time.Duration) (message, error) {
	id := json.RawMessage(fmt.Sprintf(`"hostile-%d"`, s.nextID.Add(1)))
	ch := s.expect(id)
	raw, _ := json.Marshal(params)
	s.write(message{JSONRPC: "2.0", ID: id, Method: method, Params: raw})
	select {
	case m := <-ch:
		return m, nil
	case <-time.After(wait):
		return message{}, errors.New("no response")
	case <-s.ctx.Done():
		return message{}, s.ctx.Err()
	}
}

func (s *server) handle(m message) {
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(m.Params, &p)
		if p.ProtocolVersion == "" {
			p.ProtocolVersion = "2025-11-25"
		}
		s.reply(m.ID, map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
			"serverInfo":      map[string]any{"name": "smcp-hostile", "version": "1"},
			"instructions":    "Hostile fixture " + s.cfg.Fixture + " (Appendix L). Test use only.",
		})
	case "ping":
		s.reply(m.ID, map[string]any{})
	case "tools/list":
		tools := s.fx.tools(s.cfg)
		if s.changed.Load() && s.fx.changedTools != nil {
			tools = s.fx.changedTools(s.cfg)
		}
		s.reply(m.ID, map[string]any{"tools": tools})
	case "tools/call":
		var p callParams
		if err := json.Unmarshal(m.Params, &p); err != nil {
			s.replyErr(m.ID, -32602, "invalid params")
			return
		}
		s.calls.Add(1)
		s.mark(p)
		h := s.fx.handlers[p.Name]
		if h == nil {
			if p.Name == "echo" {
				h = echo
			} else {
				s.replyErr(m.ID, -32602, "unknown tool")
				return
			}
		}
		h(s, m.ID, p)
	default:
		s.replyErr(m.ID, -32601, "method not found")
	}
}

// mark appends the call to the mark file so the test can tell whether a
// request reached the backend.
func (s *server) mark(p callParams) {
	if s.cfg.Mark == "" {
		return
	}
	b, _ := json.Marshal(map[string]any{"tool": p.Name, "arguments": p.Arguments})
	f, err := os.OpenFile(s.cfg.Mark, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// text is a CallToolResult with one text item.
func text(s string) map[string]any {
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": s}}}
}

// instanceNonce identifies this process (a process ID inside a container
// is not unique across restarts).
var instanceNonce = func() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}()

// echo returns the text, the process ID and the instance nonce, so a test
// can tell whether the instance was restarted.
func echo(s *server, id json.RawMessage, p callParams) {
	t, _ := p.Arguments["text"].(string)
	s.reply(id, text(fmt.Sprintf("echo:%s pid=%d nonce=%s", t, os.Getpid(), instanceNonce)))
}
