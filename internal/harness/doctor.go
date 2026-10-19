package harness

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Finding kinds. Every kind except "info" and "warning" makes doctor exit
// non-zero (FR-15.5).
const (
	KindServer   = "non-gateway-server" // FR-15.3, SR-4.9-1
	KindReadable = "readable-path"      // FR-15.4
	KindWritable = "settings-writable"  // SR-4.11-1
	KindPrereq   = "prerequisite"       // enforced-profile prerequisite
	KindWarning  = "warning"
	KindInfo     = "info"
)

// Finding is one doctor result.
type Finding struct {
	Kind    string `json:"kind"`
	Client  string `json:"client,omitempty"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// Fails reports whether the finding makes doctor exit non-zero.
func (f Finding) Fails() bool { return f.Kind != KindInfo && f.Kind != KindWarning }

// Report is the doctor output (text and --json carry the same findings).
type Report struct {
	Profile  string    `json:"profile"`
	Clients  []string  `json:"clients_checked"`
	Servers  []Server  `json:"servers"`
	Findings []Finding `json:"findings"`
}

// Failed reports whether any finding fails.
func (r Report) Failed() bool {
	for _, f := range r.Findings {
		if f.Fails() {
			return true
		}
	}
	return false
}

// Prereq is a check supplied by another element (the sandbox element's
// enforced-profile prerequisites); nil means not available.
type Prereq func() []Finding

// canRead reports whether the current user can read the file or list the
// directory.
func canRead(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	if fi.IsDir() {
		_, err = f.Readdirnames(1)
		return err == nil || errors.Is(err, io.EOF)
	}
	buf := make([]byte, 1)
	_, err = f.Read(buf)
	return err == nil || errors.Is(err, io.EOF)
}

func canWrite(p string) bool {
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// Doctor runs every check for the given clients (all installed clients
// when ids is empty).
func Doctor(e Env, ids []string, prereq Prereq) Report {
	r := Report{Profile: "enforced", Servers: []Server{}, Findings: []Finding{}}
	if e.Standalone {
		r.Profile = "standalone"
		r.Findings = append(r.Findings, Finding{Kind: KindInfo, Message: "Standalone profile: clients run under the Gateway's own user identity, so the operating system does not keep them from the Gateway's files (Security Limitations)"})
	}
	var clients []*Client
	if len(ids) == 0 {
		for _, c := range Clients() {
			if c.Installed(e) {
				clients = append(clients, c)
			}
		}
	} else {
		for _, id := range ids {
			c, ok := Lookup(id)
			if !ok {
				r.Findings = append(r.Findings, Finding{Kind: KindWarning, Client: id, Message: "unknown client; known: " + strings.Join(IDs(), ", ")})
				continue
			}
			clients = append(clients, c)
		}
	}
	for _, c := range clients {
		r.Clients = append(r.Clients, c.ID)
		servers, notes := c.Inventory(e)
		gateway := false
		for _, s := range servers {
			r.Servers = append(r.Servers, s)
			if s.Gateway {
				gateway = true
				continue
			}
			r.Findings = append(r.Findings, Finding{Kind: KindServer, Client: c.ID, Path: s.File,
				Message: fmt.Sprintf("%s scope configures MCP server %q (%s %s), which is not the Gateway", s.Scope, s.Name, s.Transport, s.Target)})
		}
		for _, n := range notes {
			r.Findings = append(r.Findings, Finding{Kind: KindWarning, Client: c.ID, Message: n})
		}
		if !gateway && c.ID != "grok-build" {
			r.Findings = append(r.Findings, Finding{Kind: KindWarning, Client: c.ID, Message: "the Gateway is not configured; run smcpctl clients setup " + c.ID})
		}
		if c.LockdownMechanism == "" {
			r.Findings = append(r.Findings, Finding{Kind: KindInfo, Client: c.ID, Message: "the client offers no lockdown mechanism (Appendix K); it is labelled gateway-available"})
		}
		if !c.Protected(e) {
			for _, f := range c.SettingsFiles(e) {
				if exists(f) && canWrite(f) {
					r.Findings = append(r.Findings, Finding{Kind: KindWritable, Client: c.ID, Path: f,
						Message: "the client's own file tools can write this MCP or permission settings file (no deny rule)"})
				}
			}
		}
		if ok, msg := c.CATrust(e); !ok {
			r.Findings = append(r.Findings, Finding{Kind: KindInfo, Client: c.ID, Message: "CA trust: " + msg})
		}
	}
	for _, p := range e.protectedPaths() {
		if exists(p) && canRead(p) {
			r.Findings = append(r.Findings, Finding{Kind: KindReadable, Path: p, Message: "readable by this user, who runs the clients"})
		}
	}
	if prereq != nil {
		r.Findings = append(r.Findings, prereq()...)
	} else {
		r.Findings = append(r.Findings, Finding{Kind: KindInfo, Message: "enforced-profile prerequisites were not checked: the sandbox element's check is not part of this build"})
	}
	return r
}

// WriteText renders the report.
func WriteText(w io.Writer, r Report) {
	fmt.Fprintf(w, "profile: %s\nclients checked: %s\n", r.Profile, strings.Join(r.Clients, ", "))
	if len(r.Servers) > 0 {
		fmt.Fprintln(w, "MCP servers:")
		for _, s := range r.Servers {
			mark := "NOT GATEWAY"
			if s.Gateway {
				mark = "gateway"
			}
			fmt.Fprintf(w, "  [%s] %s %s: %s (%s %s) in %s\n", mark, s.Client, s.Scope, s.Name, s.Transport, s.Target, s.File)
		}
	}
	n := 0
	for _, f := range r.Findings {
		label := "FINDING"
		if !f.Fails() {
			label = strings.ToUpper(f.Kind)
		} else {
			n++
		}
		where := ""
		if f.Client != "" {
			where += " " + f.Client
		}
		if f.Path != "" {
			where += " " + f.Path
		}
		fmt.Fprintf(w, "%s [%s]%s: %s\n", label, f.Kind, where, f.Message)
	}
	fmt.Fprintf(w, "%d findings\n", n)
}
