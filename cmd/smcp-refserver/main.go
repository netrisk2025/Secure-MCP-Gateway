// Command smcp-refserver is the reference MCP server shipped with the
// Gateway: a small stdio server with read-only demonstration tools, so the
// configuration written by `smcpctl bootstrap` runs out of the box without
// fetching anything at run time (SR-3.6-1).
//
// Tools:
//
//	echo        returns its text argument
//	time_now    returns the current UTC time
//	list_files  lists a directory under --root (only with --root)
//	read_file   reads a text file under --root, at most 256 KiB (only with --root)
//
// File access is confined to --root with os.Root, which refuses paths and
// symbolic links that leave the directory. Nothing is ever written.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Version is set by the build (-X main.Version in .goreleaser.yaml).
var Version = "0.0.0-dev"

// versionLine is what smcp-refserver --version prints, in the form of the
// other release binaries ("smcpd 1.0.0").
func versionLine() string { return "smcp-refserver " + Version }

const maxRead = 256 << 10

func main() {
	root := flag.String("root", "", "directory the file tools may read (file tools are disabled when empty)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(versionLine())
		return
	}
	srv, closeRoot, err := newServer(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "smcp-refserver:", err)
		os.Exit(1)
	}
	defer closeRoot()
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "smcp-refserver:", err)
		os.Exit(1)
	}
}

type echoArgs struct {
	Text string `json:"text" jsonschema:"text to return"`
}

type pathArgs struct {
	Path string `json:"path" jsonschema:"slash-separated path relative to the server root; empty or . for the root"`
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func toolError(s string) *mcp.CallToolResult {
	r := text(s)
	r.IsError = true
	return r
}

// clean turns a client path into an os.Root-relative path.
func clean(p string) (string, error) {
	p = path.Clean("/" + strings.TrimSpace(p))
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		p = "."
	}
	if !fs.ValidPath(p) {
		return "", errors.New("invalid path")
	}
	return p, nil
}

func newServer(rootDir string) (*mcp.Server, func(), error) {
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(bool)}
	s := mcp.NewServer(&mcp.Implementation{Name: "smcp-refserver", Version: Version}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Return the given text unchanged.", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, a echoArgs) (*mcp.CallToolResult, any, error) {
			return text(a.Text), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "time_now", Description: "Return the current time in UTC (RFC 3339).", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return text(time.Now().UTC().Format(time.RFC3339)), nil, nil
		})
	if rootDir == "" {
		return s, func() {}, nil
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, nil, err
	}
	mcp.AddTool(s, &mcp.Tool{Name: "list_files", Description: "List the entries of a directory under the server root.", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, a pathArgs) (*mcp.CallToolResult, any, error) {
			p, err := clean(a.Path)
			if err != nil {
				return toolError(err.Error()), nil, nil
			}
			entries, err := fs.ReadDir(root.FS(), p)
			if err != nil {
				// A listing failure is the tool's result, not a protocol error.
				return toolError("cannot list " + a.Path), nil, nil //nolint:nilerr // reported to the client as a tool error result
			}
			var lines []string
			for _, e := range entries {
				name := e.Name()
				if e.IsDir() {
					name += "/"
				}
				lines = append(lines, name)
			}
			sort.Strings(lines)
			return text(strings.Join(lines, "\n")), nil, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "read_file", Description: "Read a UTF-8 text file under the server root (at most 256 KiB).", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, a pathArgs) (*mcp.CallToolResult, any, error) {
			p, err := clean(a.Path)
			if err != nil {
				return toolError(err.Error()), nil, nil
			}
			f, err := root.Open(p)
			if err != nil {
				return toolError("cannot open " + a.Path), nil, nil
			}
			defer f.Close()
			if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
				return toolError(a.Path + " is not a regular file"), nil, nil
			}
			b, err := io.ReadAll(io.LimitReader(f, maxRead+1))
			if err != nil {
				return toolError("cannot read " + a.Path), nil, nil
			}
			if len(b) > maxRead {
				return toolError(a.Path + " is larger than 256 KiB"), nil, nil
			}
			if !utf8.Valid(b) {
				return toolError(a.Path + " is not UTF-8 text"), nil, nil
			}
			return text(string(b)), nil, nil
		})
	return s, func() { root.Close() }, nil
}
