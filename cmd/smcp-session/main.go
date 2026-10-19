// Command smcp-session prints Gateway session headers for client header
// helpers (FR-12.12). See docs/adapters.md.
package main

import (
	"os"

	"github.com/ethan03805/secure-mcp-gateway/internal/adapter"
)

func main() { os.Exit(adapter.SessionMain(os.Args[1:], os.Stdout, os.Stderr)) }
