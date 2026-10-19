package main

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// referenceClient is a scripted, model-free client: the suite's own MCP
// client performs what each prompt asks. It checks the harness, the policy
// and the journal assertions without spending model tokens
// (`-clients reference`, and the Go tests). It is not an Appendix K client
// and never appears in a default run.
func referenceClient() *client {
	return &client{
		ID: "reference", Name: "smcp reference client", Framework: "other",
		run: func(ctx context.Context, e *runEnv, s scenario) (string, error) {
			p, err := newProbe(ctx, e.g, e.token)
			if err != nil {
				return "", err
			}
			defer p.Close()
			switch s.ID {
			case scnCatalog:
				names, err := p.tools(ctx)
				if err != nil {
					return "", err
				}
				if slices.Contains(names, publicName(toolUngranted)) {
					_, _, err = p.call(ctx, publicName(toolUngranted), map[string]any{"path": "."})
				}
				return strings.Join(names, " "), err
			case scnAllowed:
				return callText(ctx, p, publicName(toolAllowed), map[string]any{"text": quoted(s.Prompt)})
			case scnDenied:
				return callText(ctx, p, publicName(toolLimited), map[string]any{})
			case scnApproval:
				return callText(ctx, p, publicName(toolApproval), map[string]any{"path": helloFile})
			}
			return "", fmt.Errorf("unknown scenario %s", s.ID)
		},
	}
}

func callText(ctx context.Context, p *probe, name string, args map[string]any) (string, error) {
	text, isErr, err := p.call(ctx, name, args)
	if err != nil {
		return "", err
	}
	if isErr {
		return text, fmt.Errorf("tool error: %s", text)
	}
	return text, nil
}

var quotedRe = regexp.MustCompile(`"([^"]*)"`)

func quoted(s string) string {
	if m := quotedRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}
