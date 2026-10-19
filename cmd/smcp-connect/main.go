// Command smcp-connect is a stdio MCP server that relays to a Gateway's
// Remote Access URL with OAuth device sign-in (FR-16.9). The npm package of
// the same name (packaging/npm/smcp-connect) behaves the same way. See
// docs/remote-access.md.
package main

import (
	"os"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
)

func main() { os.Exit(adapter.ConnectMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
