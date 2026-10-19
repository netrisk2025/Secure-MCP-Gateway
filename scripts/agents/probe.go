package main

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// probe is the suite's own MCP client. It uses an agent's session token to
// read the catalog that session is presented and to make calls that set up a
// scenario (for example filling the rate window before the denied
// scenario). It never stands in for the agent in an assertion.
type probe struct {
	cs *mcp.ClientSession
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func newProbe(ctx context.Context, g *gateway, token string) (*probe, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "smcp-agents-probe", Version: "1"}, nil)
	cs, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   g.endpoint,
		HTTPClient: &http.Client{Transport: bearer{token, g.hc.Transport}},
	}, nil)
	if err != nil {
		return nil, err
	}
	return &probe{cs: cs}, nil
}

func (p *probe) Close() { _ = p.cs.Close() }

// tools returns the sorted public names of the session's catalog.
func (p *probe) tools(ctx context.Context) ([]string, error) {
	var names []string
	for t, err := range p.cs.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return names, nil
}

// call calls a tool and returns its text, whether it was a tool error, and
// a protocol error.
func (p *probe) call(ctx context.Context, name string, args map[string]any) (string, bool, error) {
	res, err := p.cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "", false, err
	}
	var text strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text.WriteString(tc.Text)
		}
	}
	return text.String(), res.IsError, nil
}
