package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethan03805/secure-mcp-gateway/internal/analytics"
	"github.com/ethan03805/secure-mcp-gateway/internal/app"
	"github.com/ethan03805/secure-mcp-gateway/internal/approval"
	"github.com/ethan03805/secure-mcp-gateway/internal/graph"
	"github.com/ethan03805/secure-mcp-gateway/internal/library"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
	"github.com/ethan03805/secure-mcp-gateway/internal/remote"
	"github.com/ethan03805/secure-mcp-gateway/internal/sandbox"
	"github.com/ethan03805/secure-mcp-gateway/internal/secrets"
)

// Element states in the health report's info.elements list.
const (
	elementActive   = "active"   // running in this process
	elementDisabled = "disabled" // configured off; Detail says how to enable it
	elementDegraded = "degraded" // configured on but not working; enforcement continues
)

// element is one architecture element as wired by this daemon. The list is
// part of GET /api/v1/health/status (info.elements) and `smcpctl health`,
// so an operator and the end-to-end tests can see which elements run.
type element struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// wiring holds the components run() built, for the elements report. Fields
// set after the report function was created are read when a report is
// made, never before.
type wiring struct {
	app       *app.App
	approvals *approval.Service
	notify    string
	packages  *library.Runtime
	sandbox   *sandbox.Launcher
	secrets   *secrets.Service
	mirror    *graph.Mirror
	obs       *analytics.Service
	remote    *remote.Service
	console   bool
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// elements reports every element the daemon wires, in element order.
func (w *wiring) elements() []element {
	a := w.app
	var out []element
	add := func(id, name, state, detail string) {
		out = append(out, element{ID: id, Name: name, State: state, Detail: detail})
	}
	if a == nil {
		return out
	}
	cfg := a.Config
	add("E-01/E-02/E-08/E-12", "Harness Edge and call pipeline", elementActive, cfg.ResourceURI())
	add("E-03/E-04", "Session Approver and sessions", elementActive, plural(len(a.Store.Active()), "active session", "active sessions"))
	if snap := a.Decider.Snapshot(); snap != nil && a.Policy.Fault() == "" {
		add("E-05/E-06", "Policy Store and decisions", elementActive, "revision "+snap.Revision)
	} else {
		add("E-05/E-06", "Policy Store and decisions", elementDegraded, "no verified policy revision: every call is refused")
	}
	if w.approvals != nil {
		add("E-07", "Approval Service", elementActive, fmt.Sprintf("%s; notify %s", plural(len(w.approvals.List(approval.StatePending)), "pending approval", "pending approvals"), w.notify))
	}
	if a.Filters != nil {
		add("E-09/E-11", "Request and response inspection", elementActive, fmt.Sprintf("%s, %s",
			plural(len(a.Filters.Registered(pipeline.StageRequest)), "request filter", "request filters"),
			plural(len(a.Filters.Registered(pipeline.StageResponse)), "response filter", "response filters")))
	}
	servers := a.Registry.Servers()
	verified := 0
	for _, s := range servers {
		if s.Verified {
			verified++
		}
	}
	add("E-10", "Backend registry", elementActive, fmt.Sprintf("%s, %d from verified manifests", plural(len(servers), "server", "servers"), verified))
	if w.packages != nil {
		running := 0
		bs := w.packages.Bindings()
		for _, b := range bs {
			if b.Status == "running" {
				running++
			}
		}
		add("E-13/E-14", "Library Trust Verifier and Local Server Registry", elementActive,
			fmt.Sprintf("%d of %s running", running, plural(len(bs), "packaged server", "packaged servers")))
	}
	if w.sandbox != nil {
		add("E-15/E-16/E-17", "Server sandbox and Runtime Monitor", elementActive, "rootless Podman; profile "+a.Profile.Profile)
	} else {
		add("E-15/E-16/E-17", "Server sandbox and Runtime Monitor", elementDisabled,
			"servers run as unconfined subprocesses (standalone profile); set [runtime] sandbox = \"podman\" on Linux")
	}
	if a.Egress != nil {
		mode := "advisory (standalone)"
		if a.Profile.Profile != "standalone" {
			mode = "enforced"
		}
		add("E-18", "Egress Broker", elementActive, fmt.Sprintf("%s; %s; %d header grants", mode, plural(len(a.Egress.Instances()), "attached instance", "attached instances"), a.Egress.HeaderGrants()))
	} else {
		add("E-18", "Egress Broker", elementDisabled, "set [egress] enabled = true")
	}
	if w.secrets != nil {
		add("E-19/E-20", "Secret Vault and Secret Broker", elementActive, fmt.Sprintf("vault %s; %d fingerprints", w.secrets.Vault.ID(), w.secrets.Broker.Fingerprints().Len()))
	} else {
		add("E-19/E-20", "Secret Vault and Secret Broker", elementDisabled, "run `smcpctl secrets init` and add a [secrets] table")
	}
	export := "export off"
	if cfg.Evidence.ExportDir != "" {
		export = "export to " + cfg.Evidence.ExportDir
	}
	add("E-21", "Evidence Journal", elementActive, export)
	keysDetail := "server CA and listener certificate"
	if a.TLS.IPConstrained {
		keysDetail += "; CA has iPAddress constraints, rotate it"
	}
	add("E-22", "Key and Trust Anchor Manager", elementActive, keysDetail)
	metricsDetail := "metrics off"
	if cfg.Metrics.Enabled {
		metricsDetail = "metrics on " + cfg.Metrics.Address
	}
	add("E-23", "Health and Safety Monitor", elementActive, metricsDetail)
	if w.console {
		add("E-24", "Management console", elementActive, cfg.AdminURL()+"/")
	}
	switch {
	case w.mirror == nil || !w.mirror.Enabled():
		add("E-25/E-26/E-28", "Graph mirror", elementDisabled, "optional; set [graph] enabled = true with a local Neo4j")
	default:
		st := w.mirror.Status(context.Background(), false)
		state := elementActive
		if st.State == graph.StateUnavailable || st.State == graph.StateRefused {
			state = elementDegraded
		}
		add("E-25/E-26/E-28", "Graph mirror", state, strings.TrimSpace(st.State+" "+st.Error))
	}
	switch {
	case w.obs.Disabled():
		add("E-27/E-29-E-32", "Observation and analytics", elementDisabled, "optional; [observation] enabled = false")
	case w.obs.StoreError() != nil:
		add("E-27/E-29-E-32", "Observation and analytics", elementDegraded, "store unavailable: "+w.obs.StoreError().Error())
	default:
		add("E-27/E-29-E-32", "Observation and analytics", elementActive, "store "+w.obs.S.Store)
	}
	if w.remote != nil {
		st := w.remote.Status()
		if st.Enabled {
			add("E-33", "Remote Access Profile", elementActive, st.ResourceURI)
		} else {
			add("E-33", "Remote Access Profile", elementDisabled, "off; enable with `smcpctl remote enable`")
		}
	}
	return out
}
