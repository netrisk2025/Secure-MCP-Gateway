// Command sandbox-probe is the hostile-fixture MCP server of the
// enforced-profile integration run (scripts/ci-integration.sh): its tools
// try to open network sockets, write outside granted mounts and spawn
// processes, and report what happened. Build it with CGO_ENABLED=0 so it
// runs in the Gateway's empty root filesystem.
package main

import (
	"os"

	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox/probe"
)

func main() { os.Exit(probe.Main(os.Args[1:])) }
