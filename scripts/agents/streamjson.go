package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// Claude Code's SDK control protocol (claude -p --input-format stream-json
// --output-format stream-json --permission-prompt-tool stdio): the CLI asks
// its host, on stdout, whether it may use a tool (control_request with
// subtype can_use_tool), and the host answers on stdin (control_response).
// This is the surface an interactive person or an Agent SDK canUseTool
// callback uses. The suite plays that person: it allows the Gateway's tools
// and nothing else, so an approval-obligated call is sent to the Gateway,
// which then holds it until an approver decides with smcpctl.

type streamMsg struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Request   struct {
		Subtype  string          `json:"subtype"`
		ToolName string          `json:"tool_name"`
		Input    json.RawMessage `json:"input"`
	} `json:"request"`
	PermissionDenials []struct {
		ToolName string `json:"tool_name"`
	} `json:"permission_denials"`
}

// canUseToolAnswer is the host's decision for one can_use_tool request:
// tools of the MCP server named prefix are allowed with their input
// unchanged, every other tool is denied.
func canUseToolAnswer(m streamMsg, prefix string) map[string]any {
	var resp map[string]any
	if m.Request.Subtype != "can_use_tool" {
		resp = map[string]any{}
	} else if strings.HasPrefix(m.Request.ToolName, prefix) {
		input := m.Request.Input
		if len(input) == 0 {
			input = json.RawMessage("{}")
		}
		resp = map[string]any{"behavior": "allow", "updatedInput": input}
	} else {
		resp = map[string]any{"behavior": "deny", "message": "the conformance suite allows only the Gateway's tools"}
	}
	return map[string]any{"type": "control_response", "response": map[string]any{
		"subtype": "success", "request_id": m.RequestID, "response": resp,
	}}
}

// streamJSONSession sends prompt as the one user message, answers control
// requests until the result message arrives, then closes stdin so the CLI
// exits. Every line the CLI prints is copied to log.
func streamJSONSession(stdin io.WriteCloser, stdout io.Reader, log io.Writer, prompt, toolPrefix string) error {
	defer stdin.Close()
	enc := json.NewEncoder(stdin)
	if err := enc.Encode(map[string]any{
		"type": "user", "session_id": "", "parent_tool_use_id": nil,
		"message": map[string]any{"role": "user", "content": prompt},
	}); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	closed := false
	for sc.Scan() {
		line := sc.Bytes()
		_, _ = log.Write(append(append([]byte{}, line...), '\n'))
		var m streamMsg
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch m.Type {
		case "control_request":
			if !closed {
				if err := enc.Encode(canUseToolAnswer(m, toolPrefix)); err != nil {
					return err
				}
			}
		case "result":
			if !closed {
				closed = true
				_ = stdin.Close()
			}
		}
	}
	// Drain so the CLI never blocks on a full pipe.
	_, _ = io.Copy(log, stdout)
	return sc.Err()
}

// deniedInResult reports whether a Claude Code result message (json or
// stream-json output) lists tool in permission_denials, that is, whether
// the CLI refused the call itself instead of sending it.
func deniedInResult(output []byte, tool string) bool {
	for _, line := range bytes.Split(output, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var m streamMsg
		if json.Unmarshal(line, &m) != nil || m.Type != "result" {
			continue
		}
		for _, d := range m.PermissionDenials {
			if d.ToolName == tool {
				return true
			}
		}
	}
	return false
}
