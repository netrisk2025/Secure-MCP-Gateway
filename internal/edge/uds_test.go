package edge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/keys"
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
	"github.com/ethan03805/secure-mcp-gateway/internal/testport"
)

const udsKey = "uds bearer key 0123456789"

var udsKeyHash = func() func(t *testing.T) string {
	var h string
	return func(t *testing.T) string {
		t.Helper()
		if h == "" {
			var err error
			if h, err = keys.HashPassword(udsKey); err != nil {
				t.Fatal(err)
			}
		}
		return h
	}
}()

// udsGroup is the primary group of the user running the test, which the
// socket can be given without privileges.
func udsGroup(t *testing.T) (string, int) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("primary group: %v", err)
	}
	gid, _ := strconv.Atoi(g.Gid)
	return g.Name, gid
}

// udsHarness starts a harness with the UDS Harness Profile enabled for a
// peer with the given UID and template, and serves the socket.
func udsHarness(t *testing.T, o harnessOpts, uid int, template string) (*harness, string) {
	t.Helper()
	path := filepath.Join(testport.SocketDir(t), "h.sock")
	group, _ := udsGroup(t)
	o.toml = fmt.Sprintf("[uds]\nenabled = true\npath = %q\ngroup = %q\n[[uds.peer]]\nuid = %d\nprincipal = \"cc\"\nkey_hash = %q\ntemplate = %q\n",
		path, group, uid, udsKeyHash(t), template)
	h := newHarness(t, o)
	ln, err := h.gw.ListenUDS()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.gw.ServeUDS(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return h, path
}

// udsClient is one connection to the harness socket.
type udsClient struct {
	t       *testing.T
	c       net.Conn
	lines   chan map[string]any
	replies map[string]map[string]any // responses read while waiting for another
}

func dialUDS(t *testing.T, path string) *udsClient {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	u := &udsClient{t: t, c: c, lines: make(chan map[string]any, 64), replies: map[string]map[string]any{}}
	go func() {
		defer close(u.lines)
		sc := bufio.NewScanner(c)
		sc.Buffer(make([]byte, 1<<16), 1<<22)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Errorf("line is not one JSON-RPC message: %q", sc.Text())
				return
			}
			u.lines <- m
		}
	}()
	return u
}

func (u *udsClient) send(line string) {
	u.t.Helper()
	if strings.Contains(line, "\n") {
		u.t.Fatal("test message has a newline")
	}
	if _, err := u.c.Write([]byte(line + "\n")); err != nil {
		u.t.Fatal(err)
	}
}

// next returns the next message, or nil when the connection closed.
func (u *udsClient) next(within time.Duration) map[string]any {
	u.t.Helper()
	select {
	case m := <-u.lines:
		return m
	case <-time.After(within):
		u.t.Fatalf("no message within %s", within)
	}
	return nil
}

// reply waits for the response with the given ID, keeping other
// responses for later calls and skipping notifications.
func (u *udsClient) reply(id string) map[string]any {
	u.t.Helper()
	if m, ok := u.replies[id]; ok {
		delete(u.replies, id)
		return m
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case m, ok := <-u.lines:
			if !ok {
				u.t.Fatalf("connection closed before the reply to %s", id)
			}
			raw, _ := json.Marshal(m["id"])
			if string(raw) == id {
				return m
			}
			if _, isReply := m["id"]; isReply {
				u.replies[string(raw)] = m
			}
		case <-deadline:
			u.t.Fatalf("no reply to %s", id)
		}
	}
}

func (u *udsClient) authenticate(key string) map[string]any {
	u.t.Helper()
	u.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"method":%q,"params":{"key":%q}}`, MethodUDSAuthenticate, key))
	return u.next(10 * time.Second)
}

func errCode(m map[string]any) int {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return int(c)
}

// TestUDSPeerAndKey is FR-2.15: a session is established on the socket only
// for a registered peer UID presenting that peer's bearer key. A
// registered UID with a wrong key, an unregistered UID with the right key
// and a first message that is not the authenticate message are each
// answered -31006 and the connection is closed.
func TestUDSPeerAndKey(t *testing.T) {
	reqtest.Verifies(t, "FR-2.15")
	h, path := udsHarness(t, harnessOpts{}, os.Getuid(), "ro")

	ok := dialUDS(t, path)
	res := ok.authenticate(udsKey)
	r, _ := res["result"].(map[string]any)
	if r["sessionId"] == nil || r["principal"] != "cc" || r["template"] != "ro" {
		t.Fatalf("authenticate: %v", res)
	}
	if s := h.store.Get(r["sessionId"].(string)); s == nil || s.Listener != "uds" {
		t.Fatalf("session %+v", s)
	}

	for name, first := range map[string]string{
		"wrong key":       fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"method":%q,"params":{"key":"not the key"}}`, MethodUDSAuthenticate),
		"no authenticate": fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta),
	} {
		c := dialUDS(t, path)
		c.send(first)
		if m := c.next(10 * time.Second); errCode(m) != CodeSessionInvalid {
			t.Fatalf("%s: %v", name, m)
		}
		if m := c.next(5 * time.Second); m != nil {
			t.Fatalf("%s: connection not closed: %v", name, m)
		}
	}
	if e := h.rec.find(func(e audit.Event) bool { return e.Class == "auth_failure" && e.ReasonCode == "UDS_KEY_INVALID" }); e == nil {
		t.Fatal("no auth_failure event for the wrong key")
	}

	// The same key from a UID that is not registered.
	h2, path2 := udsHarness(t, harnessOpts{}, os.Getuid()+1, "ro")
	c := dialUDS(t, path2)
	if m := c.authenticate(udsKey); errCode(m) != CodeSessionInvalid {
		t.Fatalf("unregistered UID: %v", m)
	}
	if m := c.next(5 * time.Second); m != nil {
		t.Fatalf("unregistered UID: connection not closed: %v", m)
	}
	if e := h2.rec.find(func(e audit.Event) bool { return e.Class == "auth_failure" && e.ReasonCode == "UDS_PEER_UNREGISTERED" }); e == nil {
		t.Fatal("no auth_failure event for the unregistered UID")
	}
	if n := len(h2.store.List()); n != 0 {
		t.Fatalf("%d sessions created for an unregistered UID", n)
	}
}

// TestUDSHarnessTransport is FR-1.47: over the socket, server/discover,
// tools/list and tools/call are each answered with one newline-terminated
// JSON-RPC message, requests may be pipelined, a listen stream's
// acknowledgement and its notifications/tools/list_changed carry the
// listen request ID as subscriptionId, closing the connection ends the
// session, and notifications/cancelled cancels an in-flight call
// (udsCancellation).
func TestUDSHarnessTransport(t *testing.T) {
	reqtest.Verifies(t, "FR-1.47")
	t.Run("cancellation", udsCancellation)
	h, path := udsHarness(t, harnessOpts{}, os.Getuid(), "ro")
	c := dialUDS(t, path)
	auth := c.authenticate(udsKey)
	sid := auth["result"].(map[string]any)["sessionId"].(string)

	c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":"L","method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{%s}}}`, wireMeta))
	ack := c.next(10 * time.Second)
	if ack["method"] != "notifications/subscriptions/acknowledged" {
		t.Fatalf("listen acknowledgement: %v", ack)
	}
	if meta, _ := ack["params"].(map[string]any)["_meta"].(map[string]any); meta["io.modelcontextprotocol/subscriptionId"] != "L" {
		t.Fatalf("acknowledgement subscriptionId: %v", ack)
	}

	// Three requests written back to back.
	c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{%s}}}`, wireMeta))
	c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta))
	c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"t_echo","arguments":{"text":"over uds"},"_meta":{%s}}}`, wireMeta))
	if r := c.reply("1"); r["result"].(map[string]any)["supportedVersions"] == nil {
		t.Fatalf("server/discover: %v", r)
	}
	if r := c.reply("2"); len(r["result"].(map[string]any)["tools"].([]any)) != 3 {
		t.Fatalf("tools/list: %v", r)
	}
	r := c.reply("3")
	content, _ := r["result"].(map[string]any)["content"].([]any)
	if len(content) != 1 || content[0].(map[string]any)["text"] != "echo:over uds" {
		t.Fatalf("tools/call: %v", r)
	}
	checkResultMeta(t, "tools/call over uds", r["result"].(map[string]any))

	// A catalog change is notified on the listen stream with its ID.
	snap, err := policy.Compile([]byte(strings.Replace(strings.Replace(edgePolicy, `"r1"`, `"r2"`, 1), `"tools": ["echo", "slow", "big"]`, `"tools": ["echo"]`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.gw.ActivatePolicy("test", snap); err != nil {
		t.Fatal(err)
	}
	n := c.next(5 * time.Second)
	if n["method"] != "notifications/tools/list_changed" {
		t.Fatalf("list_changed: %v", n)
	}
	if meta, _ := n["params"].(map[string]any)["_meta"].(map[string]any); meta["io.modelcontextprotocol/subscriptionId"] != "L" {
		t.Fatalf("list_changed subscriptionId: %v", n)
	}

	c.c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for h.store.IsActive(sid) {
		if time.Now().After(deadline) {
			t.Fatal("closing the connection did not end the session")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// udsCancellation: notifications/cancelled for an in-flight tools/call on
// the socket sends notifications/cancelled southbound, and no response for
// the cancelled request is written.
func udsCancellation(t *testing.T) {
	ids := make(chan json.RawMessage, 1)
	sc := &scripted{call: func(_ func(string), id json.RawMessage, _ string) bool {
		ids <- id
		return true // never answers
	}}
	_, path := udsHarness(t, harnessOpts{raw: sc.serve, policy: southPolicy}, os.Getuid(), "rw")
	c := dialUDS(t, path)
	c.authenticate(udsKey)
	c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"t_w","arguments":{},"_meta":{%s}}}`, wireMeta))
	var id json.RawMessage
	select {
	case id = <-ids:
	case <-time.After(5 * time.Second):
		t.Fatal("the call was not dispatched")
	}
	c.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5,"reason":"user"}}`)
	deadline := time.Now().Add(5 * time.Second)
	found := false
	for !found && time.Now().Before(deadline) {
		for _, l := range sc.received() {
			var m struct {
				Method string `json:"method"`
				Params struct {
					RequestID json.RawMessage `json:"requestId"`
				} `json:"params"`
			}
			if json.Unmarshal([]byte(l), &m) == nil && m.Method == "notifications/cancelled" && string(m.Params.RequestID) == string(id) {
				found = true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatalf("no southbound notifications/cancelled for %s", id)
	}
	// The connection stays usable and the cancelled request gets nothing.
	c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{"_meta":{%s}}}`, wireMeta))
	for {
		m := c.next(5 * time.Second)
		raw, _ := json.Marshal(m["id"])
		if string(raw) == "5" {
			t.Fatalf("a response was written for the cancelled request: %v", m)
		}
		if string(raw) == "6" {
			break
		}
	}
}

// TestUDSSocketMode is SR-2.8-3: the socket is created with mode 0660 and
// owned by the configured group.
func TestUDSSocketMode(t *testing.T) {
	reqtest.Verifies(t, "SR-2.8-3")
	_, gid := udsGroup(t)
	_, path := udsHarness(t, harnessOpts{}, os.Getuid(), "ro")
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Gid) != gid {
		t.Fatalf("socket group %v, want %d", fi.Sys(), gid)
	}
}
