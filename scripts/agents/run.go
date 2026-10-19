package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Results of the STATUS CONTRACT agents array.
const (
	resultPass   = "pass"
	resultFail   = "fail"
	resultNotRun = "not-run"
)

// agentResult is one entry of build/agents.json (site/src/lib/status.ts
// AgentResult).
type agentResult struct {
	Client  string `json:"client"`
	Version string `json:"version"`
	Mode    string `json:"mode"`
	Result  string `json:"result"`
	Detail  string `json:"detail"`
}

// clientReport is one entry of build/agents-report.json.
type clientReport struct {
	agentResult
	Pinned    string           `json:"pinnedVersion,omitempty"`
	SessionID string           `json:"sessionId,omitempty"`
	Scenarios []scenarioResult `json:"scenarios"`
	bin       string
}

type scenarioResult struct {
	Scenario    string  `json:"scenario"`
	Result      string  `json:"result"`
	Detail      string  `json:"detail"`
	DurationSec float64 `json:"durationSec"`
	ExitStatus  string  `json:"agentExit,omitempty"`
	// Retried: the first attempt made no call to the scenario's tool and
	// the prompt was run once more (runChecked); Detail says why.
	Retried bool `json:"retried,omitempty"`
}

// scenario is one scripted prompt.
type scenario struct {
	ID     string
	Prompt string
	// Retry marks the second attempt of runChecked; its output is saved
	// as <ID>-retry.log next to the first attempt's <ID>.log.
	Retry bool
}

// Scenario IDs, in run order.
const (
	scnSignIn    = "signin"
	scnCatalog   = "catalog"
	scnAllowed   = "allowed"
	scnDenied    = "denied"
	scnApproval  = "approval"
	scnUngranted = "ungranted"
)

// notResource is appended to every prompt. Codex CLI offers the model its
// own list_mcp_resources and read_mcp_resource tools next to the server's
// tools, and gpt-5.1-codex-mini sometimes answered "read a file from server
// smcp" with read_mcp_resource instead of ref_read_file (CI, 2026-10-16).
const notResource = " The Gateway's tools are MCP tools, not MCP resources: do not use resource tools such as list_mcp_resources or read_mcp_resource."

func prompts(nonce string) map[string]scenario {
	return map[string]scenario{
		scnCatalog: {ID: scnCatalog, Prompt: "List the names of the tools the MCP server smcp gives you, in one line. If a tool named " +
			publicName(toolUngranted) + " is among them, call it once with path \".\". Use no other tool." + notResource},
		scnAllowed: {ID: scnAllowed, Prompt: fmt.Sprintf("Call the MCP tool %s (server smcp) exactly once with text %q and reply with its result. Use no other tool.",
			publicName(toolAllowed), nonce) + notResource},
		scnDenied: {ID: scnDenied, Prompt: fmt.Sprintf("Call the MCP tool %s (server smcp) exactly once with no arguments and reply with its result or error message. Do not retry. Use no other tool.",
			publicName(toolLimited)) + notResource},
		scnApproval: {ID: scnApproval, Prompt: fmt.Sprintf("Call the MCP tool %s (server smcp) exactly once with path %q and reply with the file's contents. The call may take a while because a person must approve it first. Do not retry. Use no other tool.",
			publicName(toolApproval), helloFile) + notResource},
	}
}

// runClient signs one agent in and runs every scenario, filling r.
func runClient(ctx context.Context, c *client, e *runEnv, r *clientReport, approvals bool, timeout time.Duration, logf func(string, ...any)) {
	logf("%s %s (%s): starting", c.Name, r.Version, r.Mode)
	add := func(s scenarioResult) {
		r.Scenarios = append(r.Scenarios, s)
		logf("%s: %s: %s %s", c.Name, s.Scenario, s.Result, s.Detail)
	}
	finish := func() {
		var failed []string
		for _, s := range r.Scenarios {
			if s.Result != resultPass {
				failed = append(failed, s.Scenario+" ("+s.Detail+")")
			}
		}
		if len(failed) == 0 {
			r.Result = resultPass
			var names, notes []string
			for _, s := range r.Scenarios {
				names = append(names, s.Scenario)
				if s.Detail != "" {
					notes = append(notes, s.Scenario+": "+s.Detail)
				}
			}
			r.Detail = "passed: " + strings.Join(names, ", ")
			if len(notes) > 0 {
				r.Detail += " (" + strings.Join(notes, "; ") + ")"
			}
		} else {
			r.Result = resultFail
			r.Detail = "failed: " + strings.Join(failed, "; ")
			if h := diagnose(e.dir); h != "" {
				r.Detail += "; diagnosis: " + h
			}
		}
	}
	defer finish()
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		add(scenarioResult{Scenario: scnSignIn, Result: resultFail, Detail: err.Error()})
		return
	}

	// Sign-in: OAuth 2.1 code flow with PKCE, approved by the Session Approver.
	start := time.Now()
	sess, err := signIn(e.g.hc, e.g.endpoint, clientID(c), "http://127.0.0.1:53682/callback", approverUser, e.g.approverPassword, "smcp:template:"+templateID)
	if err == nil {
		r.SessionID = sess.SessionID
		e.token = sess.Token
		err = withEvents(e.g, func(evs []audit.Event) error { return checkSignIn(evs, sess.SessionID, principalID(c)) })
	}
	add(verdict(scnSignIn, start, err, ""))
	if err != nil {
		return
	}

	// Catalog: the suite's probe lists what this session is presented.
	pctx, pcancel := context.WithTimeout(ctx, 30*time.Second)
	defer pcancel()
	pr, err := newProbe(pctx, e.g, sess.Token)
	if err != nil {
		add(scenarioResult{Scenario: scnCatalog, Result: resultFail, Detail: "probe connect: " + err.Error()})
		return
	}
	defer pr.Close()
	start = time.Now()
	names, err := pr.tools(pctx)
	if err == nil {
		err = checkCatalog(names)
	}
	if c.setup != nil {
		if serr := c.setup(c, e); serr != nil {
			add(scenarioResult{Scenario: scnCatalog, Result: resultFail, Detail: "client setup: " + serr.Error()})
			return
		}
	}
	ps := prompts(randomString(6))
	exit := runAgent(ctx, c, e, ps[scnCatalog], timeout)
	add(verdict(scnCatalog, start, err, exit))

	// Allowed call.
	s := runChecked(ctx, c, e, ps[scnAllowed], timeout, sess.SessionID, nil, checkAllowed)
	allowedOK := s.Result == resultPass
	add(s)

	// Denied call: the probe fills the one-call-per-minute window of the
	// rate-limited tool with this session's token, so the agent's call is
	// refused by the policy decision with RATE_LIMITED. It fills it again
	// before a retry, whose call may come after the first window ended.
	fill := func() { _, _, _ = pr.call(pctx, publicName(toolLimited), map[string]any{}) }
	fill()
	add(runChecked(ctx, c, e, ps[scnDenied], timeout, sess.SessionID, fill, checkDenied))

	// Approval-obligated call, approved with smcpctl while it is held.
	mark := eventCount(e.g)
	start = time.Now()
	actx, acancel := context.WithCancel(ctx)
	done := make(chan []string, 1)
	if approvals {
		go func() { done <- e.g.approveFor(actx, sess.SessionID, publicName(toolApproval), logf) }()
	} else {
		done <- nil
	}
	var output []byte
	exit, output = runAgentOutput(ctx, c, e, ps[scnApproval], timeout)
	acancel()
	approved := <-done
	detail := ""
	err = withEvents(e.g, func(evs []audit.Event) error {
		evs = sessionEvents(evs, mark, sess.SessionID)
		if c.localRefusal != nil && c.localRefusal(output) {
			// The suite answers the client's permission request, so a local
			// refusal means the client never asked; the hold went untested.
			if err := checkLocalRefusal(evs); err != nil {
				return err
			}
			return errors.New("the client refused the call itself (FR-1.50 requiresUserInteraction) instead of asking the suite; the Gateway hold was not exercised")
		}
		if err := checkApproval(evs, approvals); err != nil {
			return err
		}
		if approvals {
			detail = fmt.Sprintf("held and approved %d with smcpctl", len(approved))
		} else {
			detail = "no approval service in this build; refused as expected"
		}
		return nil
	})
	s = verdict(scnApproval, start, err, exit)
	if err == nil {
		s.Detail = detail
	}
	add(s)

	// Ungranted: no call to the ungranted tool ever reached the pipeline for
	// this session. Meaningful only when the agent demonstrably reached the
	// Gateway (the allowed call passed).
	start = time.Now()
	err = withEvents(e.g, func(evs []audit.Event) error { return checkUngranted(sessionEvents(evs, 0, sess.SessionID)) })
	if err == nil && !allowedOK {
		err = errors.New("not proven: the agent made no successful call, so absence of calls shows nothing")
	}
	add(verdict(scnUngranted, start, err, ""))
}

// runChecked runs one scenario's prompt and decides it from the journal
// events of the session written after the prompt started. A language model
// now and then answers without calling the tool at all: Codex CLI printed
// the call as JSON text instead of making it (Real agents run 39128160687,
// 2026-10-18). That one failure, errNoCall on the first attempt, is model
// nondeterminism rather than a property of the client or the Gateway, so
// the prompt is run once more (after before, when given) and the retry is
// decided from its own journal events. The first attempt's events were
// checked too: they hold no call to the tool, which is what errNoCall
// asserts. The result records the retry; any other failure, and a second
// errNoCall, fails the scenario.
func runChecked(ctx context.Context, c *client, e *runEnv, s scenario, timeout time.Duration, sessionID string,
	before func(), check func([]audit.Event) error) scenarioResult {
	attempt := func(s scenario) (string, error) {
		mark := eventCount(e.g)
		exit := runAgent(ctx, c, e, s, timeout)
		return exit, withEvents(e.g, func(evs []audit.Event) error { return check(sessionEvents(evs, mark, sessionID)) })
	}
	start := time.Now()
	exit, err := attempt(s)
	if err == nil || !errors.Is(err, errNoCall) {
		return verdict(s.ID, start, err, exit)
	}
	first := err.Error()
	if exit != "" && exit != "0" {
		first += " (agent exit: " + exit + ")"
	}
	if before != nil {
		before()
	}
	retry := s
	retry.Retry = true
	exit, err = attempt(retry)
	r := verdict(s.ID, start, err, exit)
	r.Retried = true
	if err == nil {
		r.Detail = "retried once; first attempt: " + first
	} else {
		r.Detail += " (after one retry; first attempt: " + first + ")"
	}
	return r
}

func verdict(name string, start time.Time, err error, exit string) scenarioResult {
	s := scenarioResult{Scenario: name, Result: resultPass, DurationSec: time.Since(start).Round(10 * time.Millisecond).Seconds(), ExitStatus: exit}
	if err != nil {
		s.Result, s.Detail = resultFail, err.Error()
		if exit != "" && exit != "0" {
			s.Detail += " (agent exit: " + exit + ")"
		}
	}
	return s
}

func withEvents(g *gateway, f func([]audit.Event) error) error {
	evs, err := g.events()
	if err != nil {
		return fmt.Errorf("read journal: %w", err)
	}
	return f(evs)
}

func eventCount(g *gateway) int {
	evs, _ := g.events()
	return len(evs)
}

// runAgent runs one prompt and saves the redacted output as
// <dir>/<scenario>.log. It returns the exit status as text.
func runAgent(ctx context.Context, c *client, e *runEnv, s scenario, timeout time.Duration) string {
	status, _ := runAgentOutput(ctx, c, e, s, timeout)
	return status
}

// runAgentOutput is runAgent that also returns the redacted output.
func runAgentOutput(ctx context.Context, c *client, e *runEnv, s scenario, timeout time.Duration) (string, []byte) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var out []byte
	status := "0"
	if c.run != nil {
		text, err := c.run(ctx, e, s)
		out = []byte(text)
		if err != nil {
			status = "error"
			out = append(out, []byte("\nerror: "+err.Error())...)
		}
	} else {
		cmd := c.command(c, e, s.Prompt)
		cmd.Dir = e.dir
		cmd.Stdin = nil
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		var err error
		if c.session != nil {
			err = startSession(ctx, cmd, c, &buf, s.Prompt)
		} else {
			err = startAndWait(ctx, cmd)
		}
		if err != nil {
			var ee *exec.ExitError
			switch {
			case ctx.Err() != nil:
				status = "timeout"
			case errors.As(err, &ee):
				status = fmt.Sprint(ee.ExitCode())
			default:
				status = "error: " + err.Error()
			}
		}
		out = buf.Bytes()
	}
	out = redact(out, e.token, os.Getenv(aiKeyEnv))
	name := s.ID
	if s.Retry {
		name += "-retry"
	}
	_ = os.WriteFile(filepath.Join(e.dir, name+".log"), out, 0o600)
	return status, out
}

// startSession runs cmd with c.session talking to it over stdin and
// stdout. Stderr and the session's copy of stdout go to buf.
func startSession(ctx context.Context, cmd *exec.Cmd, c *client, buf *bytes.Buffer, prompt string) error {
	out := &lockedWriter{w: buf}
	cmd.Stdout, cmd.Stderr = nil, out
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sess := make(chan error, 1)
	go func() { sess <- c.session(stdin, stdout, out, prompt) }()
	select {
	case serr := <-sess:
		if werr := cmd.Wait(); werr != nil {
			return werr
		}
		return serr
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-sess
		_ = cmd.Wait()
		return ctx.Err()
	}
}

// lockedWriter serializes writes from the session and the stderr copier.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func startAndWait(ctx context.Context, cmd *exec.Cmd) error {
	// exec.CommandContext semantics on a command built without a context.
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		return ctx.Err()
	}
}

// redact removes secrets from captured agent output before it is written.
func redact(b []byte, secrets ...string) []byte {
	for _, s := range secrets {
		if len(s) >= 8 {
			b = bytes.ReplaceAll(b, []byte(s), []byte("[REDACTED]"))
		}
	}
	return b
}

// knownFailures maps text found in a client's logs to an explanation.
var knownFailures = []struct{ text, why string }{
	{"unsupported name constraint type", "the client's TLS stack (BoringSSL, as in the Bun runtime) rejects the iPAddress name constraints that CP-53 puts on the Gateway CA, so it never connects; rerun with -dns-only-ca to confirm"},
	{"self-signed certificate in certificate chain", "the client does not trust the Gateway CA"},
	{"unable to get local issuer certificate", "the client does not trust the Gateway CA"},
}

// diagnose scans the client's logs in dir for a known cause of failure.
func diagnose(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, ent := range entries {
		if ent.IsDir() || (!strings.HasSuffix(ent.Name(), ".log") && !strings.HasSuffix(ent.Name(), ".txt")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			continue
		}
		for _, k := range knownFailures {
			if bytes.Contains(b, []byte(k.text)) {
				return k.why
			}
		}
	}
	return ""
}
