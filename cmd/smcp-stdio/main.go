// Command smcp-stdio is a stdio MCP server that relays to the Gateway
// harness listener (FR-12.13). See docs/adapters.md.
package main

import (
	"os"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
)

func main() { os.Exit(adapter.StdioMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
