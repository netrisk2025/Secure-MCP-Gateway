package edge

import (
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Self-asserted request metadata (FR-1.44, FR-1.45). The harness may put
// W3C trace context (traceparent, tracestate, baggage) and
// io.modelcontextprotocol/clientInfo in a request's _meta. The Gateway
// records a valid traceparent and the clientInfo name and version as
// observation attributes (pipeline.Call.TraceParent, ClientInfo) and uses
// neither anywhere else: policy.Request has no field for them, and the
// southbound request is built from the tool name and arguments with a
// fresh _meta (backend.Registry.Call), so harness trace context never
// reaches a backend.

// maxClientInfo bounds the recorded clientInfo text.
const maxClientInfo = 128

// selfAsserted returns the valid traceparent and the "name/version" text of
// clientInfo from a request's _meta; each is empty when absent or invalid.
func selfAsserted(meta mcp.Meta) (traceparent, clientInfo string) {
	if s, ok := meta["traceparent"].(string); ok && validTraceparent(s) {
		traceparent = s
	}
	if ci, ok := meta[mcp.MetaKeyClientInfo].(map[string]any); ok {
		name, _ := ci["name"].(string)
		version, _ := ci["version"].(string)
		if name != "" {
			clientInfo = printable(name)
			if version != "" {
				clientInfo += "/" + printable(version)
			}
			if len(clientInfo) > maxClientInfo {
				clientInfo = clientInfo[:maxClientInfo]
			}
		}
	}
	return traceparent, clientInfo
}

// printable drops control characters from self-asserted text.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// validTraceparent checks the W3C Trace Context traceparent format:
// version-traceid-parentid-flags in lowercase hex, version not ff, and
// neither ID all zeros. Version 00 has exactly four fields; a later
// version may append fields after the flags.
func validTraceparent(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) < 4 {
		return false
	}
	lens := []int{2, 32, 16, 2}
	for i, n := range lens {
		if len(parts[i]) != n || !lowerHex(parts[i]) {
			return false
		}
	}
	switch parts[0] {
	case "ff":
		return false
	case "00":
		if len(parts) != 4 {
			return false
		}
	}
	return strings.Trim(parts[1], "0") != "" && strings.Trim(parts[2], "0") != ""
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
