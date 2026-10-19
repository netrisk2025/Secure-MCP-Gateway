// Command smcp-hostile is the hostile backend MCP server of SRS Appendix L
// for manual runs and demonstrations: a stdio MCP server that misbehaves as
// one Appendix L row describes.
//
//	smcp-hostile -fixture HF-04
//	smcp-hostile -list
//
// It is a test fixture. Its injection text is fixed canary text, it contacts
// only the loopback canary addresses given on the command line, and its
// resource fixtures stop at fixed caps (64 processes, 256 MiB, 32 MiB of
// output). The automated suite runs the same code from its test binary;
// see docs/hostile-fixtures.md.
package main

import (
	"os"

	"github.com/ethan03805/secure-mcp-gateway/internal/hostile"
)

func main() {
	os.Exit(hostile.Main([]string{os.Args[0]}, os.Args[1:]))
}
