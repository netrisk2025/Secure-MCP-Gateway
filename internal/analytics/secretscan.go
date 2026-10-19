package analytics

import "github.com/modelcontextprotocol/go-sdk/mcp"

// maxSecretScan bounds the result text the response probe scans for
// secret fingerprints, as the response features bound the text they read.
const maxSecretScan = 4 << 20

// SetSecretScanner registers the Secret Broker's leak fingerprints with
// the Observation Collector (FR-6.10): scan returns the number of
// fingerprint matches in its input. The observe-request probe scans the
// arguments and the observe-response probe the result's text parts; the
// collector reports the larger of its own count and the filter chain's as
// secret_fingerprint_matches (P-142). nil unregisters.
func (s *Service) SetSecretScanner(scan func([]byte) int) {
	if s == nil {
		return
	}
	if scan == nil {
		s.scanner.Store(nil)
		return
	}
	s.scanner.Store(&scan)
}

func (s *Service) secretScanner() func([]byte) int {
	if p := s.scanner.Load(); p != nil {
		return *p
	}
	return nil
}

// resultTexts returns the text parts of a result, up to maxSecretScan
// bytes in all.
func resultTexts(res *mcp.CallToolResult) []string {
	if res == nil {
		return nil
	}
	var out []string
	n := 0
	for _, c := range res.Content {
		t, ok := c.(*mcp.TextContent)
		if !ok {
			continue
		}
		s := t.Text
		if n+len(s) > maxSecretScan {
			s = s[:maxSecretScan-n]
		}
		out = append(out, s)
		if n += len(s); n >= maxSecretScan {
			break
		}
	}
	return out
}
