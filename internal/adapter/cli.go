package adapter

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// HelperTimeout bounds smcp-session; Claude Code gives a headersHelper 10
// seconds.
var HelperTimeout = 9 * time.Second

// SessionMain is smcp-session (FR-12.12): print a JSON object of request
// headers for the Claude Code headersHelper hook, or with --env NAME the line
// NAME=<Authorization value> (Codex env_http_headers, Hermes). It never
// prints the token anywhere else.
func SessionMain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("smcp-session", flag.ContinueOnError)
	fs.SetOutput(stderr)
	credPath := fs.String("credentials", DefaultPath(), "CP-43 credential file")
	envName := fs.String("env", "", "print NAME=<Authorization value> for a static header instead of JSON (Hermes)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "smcp-session %s\n", Version)
		return 0
	}
	creds, err := Load(*credPath)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-session:", err)
		return 1
	}
	s, err := NewSession(creds)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-session:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), HelperTimeout)
	defer cancel()
	defer s.HTTP.CloseIdleConnections()
	h, err := s.Headers(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-session:", err)
		return 1
	}
	if *envName != "" {
		fmt.Fprintf(stdout, "%s=%s\n", *envName, h["Authorization"])
		return 0
	}
	if err := json.NewEncoder(stdout).Encode(h); err != nil {
		return 1
	}
	return 0
}

func relayLogger(stderr io.Writer, verbose bool) *slog.Logger {
	lvl := slog.LevelWarn
	if verbose {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: lvl}))
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// StdioMain is smcp-stdio (FR-12.13): a stdio MCP server that relays to the
// Gateway harness listener with a session from the credential file.
func StdioMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("smcp-stdio", flag.ContinueOnError)
	fs.SetOutput(stderr)
	credPath := fs.String("credentials", DefaultPath(), "CP-43 credential file")
	verbose := fs.Bool("v", false, "log each relay failure and debug detail to standard error")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "smcp-stdio %s\n", Version)
		return 0
	}
	creds, err := Load(*credPath)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-stdio:", err)
		return 1
	}
	if creds.Gateway.Socket != "" { // UDS Harness Profile
		ctx, cancel := signalContext()
		defer cancel()
		if err := RunUDS(ctx, creds.Gateway.Socket, creds.Gateway.UDSKey, stdin, stdout); err != nil {
			fmt.Fprintln(stderr, "smcp-stdio:", err)
			return 1
		}
		return 0
	}
	s, err := NewSession(creds)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-stdio:", err)
		return 1
	}
	ctx, cancel := signalContext()
	defer cancel()
	defer s.HTTP.CloseIdleConnections()
	r := &Relay{URL: creds.Gateway.URL, HTTP: s.HTTP, Tokens: s, In: stdin, Out: stdout, Log: relayLogger(stderr, *verbose)}
	if err := r.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "smcp-stdio:", err)
		return 1
	}
	return 0
}

// ConnectMain is smcp-connect (FR-16.9): a stdio MCP server that relays to
// a Remote Access URL, signing in with the device authorization grant.
//
//	smcp-connect [--url URL] [--credentials FILE] [--ca FILE]   relay
//	smcp-connect login [--url URL] ...                          sign in only
//	smcp-connect logout [--credentials FILE]                    forget tokens
func ConnectMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	mode := "relay"
	if len(args) > 0 && (args[0] == "login" || args[0] == "logout") {
		mode, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("smcp-connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	credPath := fs.String("credentials", DefaultPath(), "CP-43 credential file")
	gwURL := fs.String("url", os.Getenv("SMCP_URL"), "Remote Access MCP URL, https://<public name>/mcp")
	ca := fs.String("ca", "", "CA file to trust instead of the system roots (testing a tunnel with a private CA)")
	clientID := fs.String("client-id", "", "pre-registered client ID (skips dynamic registration)")
	scope := fs.String("scope", "", "OAuth scope, for example smcp:template:remote")
	verbose := fs.Bool("v", false, "debug logging to standard error")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "smcp-connect %s\n", Version)
		return 0
	}
	secret := os.Getenv("SMCP_CLIENT_SECRET")
	creds, err := LoadOrNew(*credPath)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-connect:", err)
		return 1
	}
	if mode == "logout" {
		creds.Session = SessionSection{}
		if err := creds.Save(); err != nil {
			fmt.Fprintln(stderr, "smcp-connect:", err)
			return 1
		}
		fmt.Fprintln(stderr, "smcp-connect: tokens removed from", creds.Path())
		return 0
	}
	if *gwURL != "" && creds.Gateway.URL != "" && *gwURL != creds.Gateway.URL {
		fmt.Fprintf(stderr, "smcp-connect: %s is for %s; use --credentials with another file for %s\n", creds.Path(), creds.Gateway.URL, *gwURL)
		return 1
	}
	if *gwURL != "" {
		creds.Gateway.URL = *gwURL
	}
	if *ca != "" {
		creds.Gateway.CAFile = *ca
	}
	if *clientID != "" {
		creds.Client.ID = *clientID
	}
	if secret != "" {
		creds.Client.Secret = secret
	}
	if creds.Gateway.URL == "" {
		fmt.Fprintln(stderr, "smcp-connect: --url is required on first use")
		return 2
	}
	h, err := NewHTTPClient(creds.Gateway)
	if err != nil {
		fmt.Fprintln(stderr, "smcp-connect:", err)
		return 1
	}
	defer h.CloseIdleConnections()
	ctx, cancel := signalContext()
	defer cancel()
	sess := &Session{Creds: creds, HTTP: h, Now: time.Now}
	needLogin := mode == "login" || (creds.Session.AccessToken == "" && creds.Session.RefreshToken == "")
	if needLogin {
		md, err := (&Login{Creds: creds, HTTP: h, Prompt: stderr, Scope: *scope}).Run(ctx)
		if err != nil {
			fmt.Fprintln(stderr, "smcp-connect:", err)
			return 1
		}
		sess.TokenURL = md.TokenEndpoint
		if mode == "login" {
			return 0
		}
	} else if md, err := Discover(ctx, h, creds.Gateway.URL); err == nil {
		sess.TokenURL = md.TokenEndpoint
	}
	r := &Relay{URL: creds.Gateway.URL, HTTP: h, Tokens: sess, In: stdin, Out: stdout, Log: relayLogger(stderr, *verbose)}
	if err := r.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "smcp-connect:", err)
		return 1
	}
	return 0
}
