package main

// FR-3.25 real-harness approval run (-approval-acceptance). Claude Code at
// the pinned version calls an approval-obligated tool of a fresh Gateway
// four times:
//
//	console   the held call is approved from the Approvals view (G-13), in a
//	          real browser driven by console/e2e/approve-held.mjs
//	smcpctl   the held call is approved with `smcpctl approvals approve`
//	denied    the held call is denied from the Approvals view
//	hold      nobody decides; the call reaches the CP-45 hold bound
//
// Each outcome is decided from the journal, as in the conformance suite,
// and the harness-visible text (the tool result Claude Code received, and
// its final reply) is written to a Markdown transcript for
// docs/verification/.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// acceptanceHold is the CP-45 hold bound of the run. Shorter than the
// default 120 s to keep the run short; long enough for a browser to sign in
// and decide.
const acceptanceHold = 60 * time.Second

type acceptanceCase struct {
	ID, Title string
	// decide runs while Claude Code waits; nil means nobody decides.
	decide func(ctx context.Context, g *gateway, sessionID, tool string) (string, error)
	// untilCancel is true when decide runs until its context ends (smcpctl
	// polling); otherwise it returns on its own and the run waits for it.
	untilCancel bool
	// check decides the outcome from the session's journal events since the
	// case started and the harness-visible tool result.
	check func(evs []audit.Event, toolResult string, isError bool, marker string) error
}

// harnessView is what Claude Code saw and said in one case, from its
// stream-json output.
type harnessView struct {
	ToolUse     string // tool name and input as Claude Code sent them
	ToolResult  string // the tool result content Claude Code received
	ResultError bool   // is_error of that tool result
	Reply       string // Claude Code's final reply (result message)
}

// parseHarnessView extracts the tool call, tool result and final reply
// from Claude Code's stream-json output.
func parseHarnessView(out []byte, tool string) harnessView {
	var v harnessView
	for _, line := range bytes.Split(out, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var m struct {
			Type    string `json:"type"`
			Result  string `json:"result"`
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch m.Type {
		case "result":
			v.Reply = m.Result
		case "assistant", "user":
			var blocks []struct {
				Type    string          `json:"type"`
				Name    string          `json:"name"`
				Input   json.RawMessage `json:"input"`
				Content json.RawMessage `json:"content"`
				IsError bool            `json:"is_error"`
			}
			if json.Unmarshal(m.Message.Content, &blocks) != nil {
				continue
			}
			for _, b := range blocks {
				switch {
				case b.Type == "tool_use" && b.Name == tool && v.ToolUse == "":
					v.ToolUse = b.Name + " " + string(b.Input)
				case b.Type == "tool_result" && v.ToolResult == "":
					v.ToolResult, v.ResultError = toolResultText(b.Content), b.IsError
				}
			}
		}
	}
	return v
}

// toolResultText flattens a tool_result content (a string or text blocks).
func toolResultText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return string(raw)
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// approvalOutcomes returns the approval events of tool in evs by outcome.
func approvalOutcomes(evs []audit.Event, tool string) map[string]audit.Event {
	out := map[string]audit.Event{}
	for _, e := range evs {
		if e.Class != "approval" {
			continue
		}
		if d, ok := e.Detail.(map[string]any); ok && d["tool"] == tool {
			if _, seen := out[e.Outcome]; !seen {
				out[e.Outcome] = e
			}
		}
	}
	return out
}

func approverOf(e audit.Event) string {
	if d, ok := e.Detail.(map[string]any); ok {
		if s, ok := d["approver"].(string); ok {
			return s
		}
	}
	return ""
}

// checkApprovedCase: the call was held, approved by the expected kind of
// approver, consumed and delivered, and the harness received the file.
func checkApprovedCase(byConsole bool) func([]audit.Event, string, bool, string) error {
	return func(evs []audit.Event, result string, isError bool, marker string) error {
		if err := checkApproval(evs, true); err != nil {
			return err
		}
		a := approvalOutcomes(evs, toolApproval)["approved"]
		who := approverOf(a)
		if byConsole && !strings.HasPrefix(who, "admin:") {
			return fmt.Errorf("approved by %q, want the console Administrator (admin:...)", who)
		}
		if !byConsole && strings.HasPrefix(who, "admin:") {
			return fmt.Errorf("approved by %q, want smcpctl", who)
		}
		if isError || !strings.Contains(result, marker) {
			return fmt.Errorf("harness did not receive the file content (is_error %v): %q", isError, result)
		}
		return nil
	}
}

func checkDeniedCase(evs []audit.Event, result string, isError bool, _ string) error {
	o := approvalOutcomes(evs, toolApproval)
	if _, ok := o["requested"]; !ok {
		return errors.New("no approval requested event")
	}
	if _, ok := o["denied"]; !ok {
		return errors.New("no approval denied event")
	}
	order, by := callsTo(evs, toolApproval)
	for _, c := range order {
		if hasPhase(by[c], audit.PhaseDispatched, "") {
			return fmt.Errorf("denied call %s was dispatched", c)
		}
	}
	if !isError || !strings.Contains(result, "denied") {
		return fmt.Errorf("harness did not receive the denial (is_error %v): %q", isError, result)
	}
	return nil
}

func checkHoldCase(evs []audit.Event, result string, isError bool, _ string) error {
	o := approvalOutcomes(evs, toolApproval)
	if _, ok := o["requested"]; !ok {
		return errors.New("no approval requested event")
	}
	for _, k := range []string{"approved", "denied", "consumed"} {
		if _, ok := o[k]; ok {
			return fmt.Errorf("unexpected approval %s event", k)
		}
	}
	order, by := callsTo(evs, toolApproval)
	for _, c := range order {
		if hasPhase(by[c], audit.PhaseDispatched, "") {
			return fmt.Errorf("undecided call %s was dispatched", c)
		}
	}
	if !isError || !strings.Contains(result, "needs approval") || !strings.Contains(result, "/approvals/") {
		return fmt.Errorf("harness did not receive the approval-required error with its link (is_error %v): %q", isError, result)
	}
	return nil
}

// consoleDecide runs console/e2e/approve-held.mjs.
func consoleDecide(decision string) func(context.Context, *gateway, string, string) (string, error) {
	return func(ctx context.Context, g *gateway, _ string, tool string) (string, error) {
		cmd := exec.CommandContext(ctx, "node", "e2e/approve-held.mjs", g.adminURL, g.adminPWFile, tool, decision,
			"FR-3.25 real-harness approval run: "+decision+" from G-13")
		cmd.Dir = filepath.Join(g.root, "console")
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return strings.TrimSpace(out.String()), err
	}
}

func smcpctlApprove(ctx context.Context, g *gateway, sessionID, tool string) (string, error) {
	ids := g.approveFor(ctx, sessionID, tool, func(string, ...any) {})
	if len(ids) == 0 {
		return "", errors.New("no pending approval was approved with smcpctl")
	}
	return "smcpctl approvals approve " + strings.Join(ids, " ") + " --yes", nil
}

func acceptanceCases() []acceptanceCase {
	return []acceptanceCase{
		{ID: "console", Title: "Held call approved from the Approvals view (G-13)", decide: consoleDecide("approve"), check: checkApprovedCase(true)},
		{ID: "smcpctl", Title: "Held call approved with smcpctl approvals", decide: smcpctlApprove, untilCancel: true, check: checkApprovedCase(false)},
		{ID: "denied", Title: "Held call denied from the Approvals view (G-13)", decide: consoleDecide("deny"), check: checkDeniedCase},
		{ID: "hold", Title: "Held call that reaches the hold bound", check: checkHoldCase},
	}
}

type caseReport struct {
	acceptanceCase
	File, Marker string
	Prompt       string
	View         harnessView
	Decision     string
	DecideErr    string
	Approvals    []audit.Event
	Calls        []audit.Event
	Duration     time.Duration
	Exit         string
	Err          error
}

// runApprovalAcceptance runs the four FR-3.25 cases with Claude Code and
// writes the transcript to transcriptPath.
func runApprovalAcceptance(ctx context.Context, o options, transcriptPath string, stdout io.Writer) error {
	logf := func(format string, a ...any) { fmt.Fprintf(stdout, "==> "+format+"\n", a...) }
	root, err := repoRoot()
	if err != nil {
		return err
	}
	c := claudeCode()
	bin := findBin(c.Bins)
	if bin == "" {
		return errors.New("claude not found")
	}
	if !o.local && os.Getenv(aiKeyEnv) == "" {
		return errors.New(aiKeyEnv + " is not set (or run with -local)")
	}
	version := clientVersion(ctx, bin)
	pinned, err := loadPinned(filepath.Join(root, o.matrix))
	if err != nil {
		return err
	}
	work := o.work
	if work == "" {
		if work, err = os.MkdirTemp("", "smcp-fr325-"); err != nil {
			return err
		}
		if !o.keep {
			defer os.RemoveAll(work)
		}
	}
	extraConfig = fmt.Sprintf("\n[limits]\napproval_hold = %q\n", acceptanceHold.String())
	g, err := startGateway(ctx, root, work, []*client{c}, false, false, logf)
	if err != nil {
		return err
	}
	defer g.stop()
	cases := acceptanceCases()
	reports := make([]*caseReport, len(cases))
	for i, k := range cases {
		marker := "fr325-" + k.ID + "-" + randomString(8)
		file := "fr325-" + k.ID + ".txt"
		if err := os.WriteFile(filepath.Join(g.dir, "sandbox", file), []byte(marker+"\n"), 0o644); err != nil {
			return err
		}
		reports[i] = &caseReport{acceptanceCase: k, File: file, Marker: marker}
	}

	e := &runEnv{g: g, dir: filepath.Join(work, "agents", c.ID), local: o.local, maxTurns: o.maxTurns, bin: bin}
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	sess, err := signIn(g.hc, g.endpoint, clientID(c), "http://127.0.0.1:53682/callback", approverUser, g.approverPassword, "smcp:template:"+templateID)
	if err != nil {
		return fmt.Errorf("sign-in: %w", err)
	}
	e.token = sess.Token
	if err := c.setup(c, e); err != nil {
		return err
	}
	tool := publicName(toolApproval)
	for _, r := range reports {
		r.Prompt = fmt.Sprintf("Call the MCP tool %s (server smcp) exactly once with path %q and reply with the file's contents, or with the exact error text if the call fails. The call may take a while because a person must approve it first. Do not retry. Use no other tool.",
			tool, r.File) + notResource
		mark := eventCount(g)
		start := time.Now()
		dctx, dcancel := context.WithCancel(ctx)
		done := make(chan struct{})
		if r.decide != nil {
			go func() {
				defer close(done)
				d, derr := r.decide(dctx, g, sess.SessionID, tool)
				r.Decision = d
				if derr != nil && (!r.untilCancel || dctx.Err() == nil || d == "") {
					r.DecideErr = derr.Error()
				}
			}()
		} else {
			close(done)
		}
		logf("%s: running Claude Code", r.ID)
		var out []byte
		r.Exit, out = runAgentOutput(ctx, c, e, scenario{ID: "fr325-" + r.ID, Prompt: r.Prompt}, o.timeout)
		r.Duration = time.Since(start)
		if !r.untilCancel {
			<-done // the browser finishes on its own
		}
		dcancel()
		<-done
		r.View = parseHarnessView(out, "mcp__smcp__"+tool)
		evs, jerr := g.events()
		if jerr != nil {
			return jerr
		}
		evs = sessionEvents(evs, mark, sess.SessionID)
		for _, ev := range evs {
			switch {
			case ev.Class == "approval":
				r.Approvals = append(r.Approvals, ev)
			case (ev.Class == "call" || ev.Class == "decision") && backendTool(ev) == toolApproval:
				r.Calls = append(r.Calls, ev)
			}
		}
		r.Err = r.check(evs, r.View.ToolResult, r.View.ResultError, r.Marker)
		if r.Err == nil && r.DecideErr != "" {
			r.Err = errors.New("decision step: " + r.DecideErr)
		}
		if r.ID == "hold" && r.Err == nil && r.Duration < acceptanceHold {
			r.Err = fmt.Errorf("the call ended after %s, before the %s hold bound", r.Duration.Round(time.Second), acceptanceHold)
		}
		logf("%s: %s", r.ID, verdictText(r.Err))
	}
	g.stop()
	vout, verr := g.verifyJournal(ctx)
	logf("journal verify: %s", vout)
	md := acceptanceTranscript(reports, version, pinned[c.Name], c.mode(o.local), vout, verr)
	md = string(redact([]byte(md), e.token, os.Getenv(aiKeyEnv)))
	if err := os.WriteFile(transcriptPath, []byte(md), 0o644); err != nil {
		return err
	}
	logf("transcript written to %s", transcriptPath)
	for _, r := range reports {
		if r.Err != nil {
			return fmt.Errorf("case %s failed: %w", r.ID, r.Err)
		}
	}
	return verr
}

func verdictText(err error) string {
	if err != nil {
		return "fail: " + err.Error()
	}
	return "pass"
}

// acceptanceTranscript renders the run as Markdown.
func acceptanceTranscript(reports []*caseReport, version, pinned, mode, verify string, verr error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# FR-3.25 transcript\n\nGenerated by `go run ./scripts/agents -approval-acceptance` on %s.\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Claude Code %s (pinned %s), mode %s, model %s\n", version, orDash(pinned), mode, modelClaude)
	fmt.Fprintf(&b, "- CP-45 hold bound `limits.approval_hold = %q`\n", acceptanceHold.String())
	fmt.Fprintf(&b, "- Journal verification after shutdown: %s\n", strings.ReplaceAll(verify, "\n", " "))
	if verr != nil {
		fmt.Fprintf(&b, "- Journal verification error: %v\n", verr)
	}
	b.WriteString("\nThe tool result is the text Claude Code received from the Gateway for the call, copied from its stream-json output. The reply is Claude Code's final message. Journal events are those of the session written while the case ran.\n")
	for i, r := range reports {
		fmt.Fprintf(&b, "\n## Case %d: %s\n\n", i+1, r.Title)
		fmt.Fprintf(&b, "Result: %s. Duration %s, Claude Code exit status %s.\n\n", verdictText(r.Err), r.Duration.Round(100*time.Millisecond), r.Exit)
		fmt.Fprintf(&b, "Prompt:\n\n~~~~\n%s\n~~~~\n\n", r.Prompt)
		fmt.Fprintf(&b, "Tool call sent by Claude Code:\n\n~~~~\n%s\n~~~~\n\n", orDash(r.View.ToolUse))
		if r.Decision != "" {
			fmt.Fprintf(&b, "Decision step:\n\n~~~~\n%s\n~~~~\n\n", r.Decision)
		}
		fmt.Fprintf(&b, "Tool result received by Claude Code (is_error %v):\n\n~~~~\n%s\n~~~~\n\n", r.View.ResultError, orDash(r.View.ToolResult))
		fmt.Fprintf(&b, "Final reply:\n\n~~~~\n%s\n~~~~\n\n", orDash(strings.TrimSpace(r.View.Reply)))
		b.WriteString("Journal events:\n\n| Time | Class | Phase | Outcome | Reason | Approver |\n|---|---|---|---|---|---|\n")
		evs := append(append([]audit.Event{}, r.Calls...), r.Approvals...)
		slices.SortStableFunc(evs, func(a, b audit.Event) int { return strings.Compare(a.Time, b.Time) })
		for _, ev := range evs {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", ev.Time, ev.Class, orDash(string(ev.Phase)), orDash(ev.Outcome), orDash(ev.ReasonCode), orDash(approverOf(ev)))
		}
	}
	return b.String()
}
