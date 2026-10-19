package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

func TestCanUseToolAnswer(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")
	var m streamMsg
	if err := json.Unmarshal([]byte(`{"type":"control_request","request_id":"r1","request":{"subtype":"can_use_tool","tool_name":"mcp__smcp__ref_read_file","input":{"path":"hello.txt"}}}`), &m); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(canUseToolAnswer(m, "mcp__smcp__"))
	want := `{"response":{"request_id":"r1","response":{"behavior":"allow","updatedInput":{"path":"hello.txt"}},"subtype":"success"},"type":"control_response"}`
	if string(b) != want {
		t.Fatalf("allow answer\n got %s\nwant %s", b, want)
	}
	m.Request.ToolName = "Bash"
	b, _ = json.Marshal(canUseToolAnswer(m, "mcp__smcp__"))
	if !strings.Contains(string(b), `"behavior":"deny"`) {
		t.Fatalf("a non-Gateway tool must be denied: %s", b)
	}
	m.Request.ToolName, m.Request.Input = "mcp__smcp__ref_time_now", nil
	b, _ = json.Marshal(canUseToolAnswer(m, "mcp__smcp__"))
	if !strings.Contains(string(b), `"updatedInput":{}`) {
		t.Fatalf("empty input must be sent as {}: %s", b)
	}
}

// TestStreamJSONSession plays the CLI side of the protocol over pipes.
func TestStreamJSONSession(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")
	inR, inW := io.Pipe()   // session -> fake CLI (the CLI's stdin)
	outR, outW := io.Pipe() // fake CLI -> session (the CLI's stdout)
	cli := make(chan []string, 1)
	go func() {
		var got []string
		sc := bufio.NewScanner(inR)
		sc.Scan()
		got = append(got, sc.Text()) // the user message
		io.WriteString(outW, `{"type":"system","subtype":"init"}`+"\n")
		io.WriteString(outW, `{"type":"control_request","request_id":"r9","request":{"subtype":"can_use_tool","tool_name":"mcp__smcp__ref_read_file","input":{"path":"hello.txt"}}}`+"\n")
		sc.Scan()
		got = append(got, sc.Text()) // the answer
		io.WriteString(outW, `{"type":"result","subtype":"success","permission_denials":[]}`+"\n")
		if sc.Scan() { // stdin must be closed after the result
			got = append(got, "unexpected: "+sc.Text())
		}
		outW.Close()
		cli <- got
	}()
	var log bytes.Buffer
	if err := streamJSONSession(inW, outR, &log, "call the tool", "mcp__smcp__"); err != nil {
		t.Fatal(err)
	}
	got := <-cli
	if len(got) != 2 {
		t.Fatalf("exchange: %q", got)
	}
	var user struct {
		Type    string `json:"type"`
		Message struct {
			Role, Content string
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(got[0]), &user); err != nil || user.Type != "user" || user.Message.Role != "user" || user.Message.Content != "call the tool" {
		t.Fatalf("user message %s (%v)", got[0], err)
	}
	if !strings.Contains(got[1], `"request_id":"r9"`) || !strings.Contains(got[1], `"behavior":"allow"`) {
		t.Fatalf("answer %s", got[1])
	}
	if !strings.Contains(log.String(), `"type":"result"`) || !strings.Contains(log.String(), "can_use_tool") {
		t.Fatalf("log must hold every CLI line: %s", log.String())
	}
}

func TestDeniedInResult(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")
	tool := "mcp__smcp__ref_read_file"
	refused := `{"type":"control_request","request":{"subtype":"can_use_tool","tool_name":"` + tool + `"}}` + "\n" +
		`{"type":"result","permission_denials":[{"tool_name":"` + tool + `","tool_use_id":"x"}]}` + "\n"
	if !deniedInResult([]byte(refused), tool) {
		t.Fatal("refusal in permission_denials not found")
	}
	// A permission request naming the tool is not a refusal.
	asked := `{"type":"control_request","request":{"subtype":"can_use_tool","tool_name":"` + tool + `"}}` + "\n" +
		`{"type":"result","permission_denials":[]}` + "\n"
	if deniedInResult([]byte(asked), tool) {
		t.Fatal("a permission request was taken for a refusal")
	}
	if deniedInResult([]byte("not json\n"), tool) {
		t.Fatal("non-JSON output taken for a refusal")
	}
}

func TestBrokenVerdict(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")
	rep := func(result string, allowed string) *clientReport {
		return &clientReport{agentResult: agentResult{Client: "c", Result: result},
			Scenarios: []scenarioResult{{Scenario: scnAllowed, Result: allowed}}}
	}
	if err := brokenVerdict([]*clientReport{rep(resultFail, resultPass), rep(resultNotRun, "")}); err != nil {
		t.Fatalf("failing client that reached the Gateway: %v", err)
	}
	if err := brokenVerdict([]*clientReport{rep(resultPass, resultPass)}); err == nil {
		t.Fatal("a client that passed against the broken Gateway was accepted")
	}
	if err := brokenVerdict([]*clientReport{rep(resultFail, resultFail)}); err == nil {
		t.Fatal("a client that never reached the Gateway was accepted")
	}
	if err := brokenVerdict([]*clientReport{rep(resultNotRun, "")}); err == nil {
		t.Fatal("a check with no client run was accepted")
	}
}

func TestPromptsSayToolNotResource(t *testing.T) {
	reqtest.Partial(t, "FR-15.8")
	for id, s := range prompts("n") {
		if !strings.HasSuffix(s.Prompt, notResource) {
			t.Errorf("%s prompt lacks the not-a-resource sentence: %s", id, s.Prompt)
		}
	}
}
