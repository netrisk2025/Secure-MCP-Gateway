package consoleapi

import (
	"net/http"
	"sort"

	"github.com/ethan03805/secure-mcp-gateway/internal/backend"
	"github.com/ethan03805/secure-mcp-gateway/internal/config"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// ServerView is the JSON form of a configured backend server.
type ServerView struct {
	Alias string `json:"alias"`
	// State is "running" for a launched server and "not_running" for a
	// configured server the registry does not hold.
	State           string   `json:"state"`
	Revision        string   `json:"revision,omitempty"`
	Era             string   `json:"era,omitempty"`
	Verified        bool     `json:"verified"`
	ManifestSource  string   `json:"manifest_source,omitempty"`
	ToolCount       int      `json:"tool_count"`
	Command         string   `json:"command"`
	Args            []string `json:"args"`
	Dir             string   `json:"dir,omitempty"`
	EnvKeys         []string `json:"env_keys"`
	SecretSlots     []string `json:"secret_slots"`
	RiskClasses     []string `json:"risk_classes"`
	Launcher        string   `json:"launcher"`
	Confined        bool     `json:"confined"`
	OversizedFrames uint64   `json:"oversized_frames"`
	// SuspendedTools are the revision's tools the registry holds as
	// suspended by the import-time metadata scan (SR-5.9-2).
	SuspendedTools []pipeline.WithheldTool `json:"suspended_tools"`
}

// ToolView is one backend tool of a server.
type ToolView struct {
	Name        string `json:"name"`
	PublicName  string `json:"public_name"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Revision    string `json:"revision"`
	InputSchema any    `json:"input_schema,omitempty"`
	Annotations any    `json:"annotations,omitempty"`
}

func keysOf(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c *Console) viewServer(sc config.Server, s *backend.Server) ServerView {
	l := c.d.Servers.Launcher()
	v := ServerView{Alias: sc.Alias, State: "not_running", Command: sc.Command, Args: append([]string{}, sc.Args...), Dir: sc.Dir,
		EnvKeys: keysOf(sc.Env), SecretSlots: keysOf(sc.SecretEnv), RiskClasses: append([]string{}, sc.RiskClasses...), SuspendedTools: []pipeline.WithheldTool{}}
	if l != nil {
		v.Launcher, v.Confined = l.Name(), l.Confined()
	}
	if s != nil {
		v.State, v.Revision, v.Era, v.Verified, v.ManifestSource, v.ToolCount = "running", s.Revision, s.Era, s.Verified, s.ManifestSource, len(s.Tools)
		v.OversizedFrames = s.OversizedFrames()
		v.SuspendedTools = append(v.SuspendedTools, s.SuspendedTools...)
	}
	return v
}

func (c *Console) listServers(w http.ResponseWriter, r *http.Request) {
	running := c.d.Servers.Servers()
	out := []ServerView{}
	for _, sc := range c.d.Config.Servers {
		out = append(out, c.viewServer(sc, running[sc.Alias]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

func toolViews(s *backend.Server) []ToolView {
	out := []ToolView{}
	if s == nil {
		return out
	}
	for _, t := range s.Tools {
		tv := ToolView{Name: t.Name, PublicName: backend.PublicName(s.Alias, t.Name), Title: t.Title, Description: t.Description,
			Revision: s.Revision + "/" + t.Name, InputSchema: t.InputSchema}
		if t.Annotations != nil {
			tv.Annotations = t.Annotations
		}
		out = append(out, tv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (c *Console) getServer(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("alias")
	for _, sc := range c.d.Config.Servers {
		if sc.Alias == alias {
			s := c.d.Servers.Servers()[alias]
			writeJSON(w, http.StatusOK, map[string]any{"server": c.viewServer(sc, s), "tools": toolViews(s)})
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "no server with this alias is configured")
}

// catalog reports, per Session Allow template of the active policy, the
// public tools a session on that template is offered, and every public
// tool of the running servers.
func (c *Console) catalog(w http.ResponseWriter, r *http.Request) {
	type grant struct {
		PublicName string   `json:"public_name"`
		Server     string   `json:"server"`
		Tool       string   `json:"tool"`
		RuleID     string   `json:"rule_id"`
		Approval   bool     `json:"approval"`
		Filters    []string `json:"filters"`
		// Available is false when the policy names a tool no running server
		// offers; such a grant is not in any session's catalog.
		Available bool `json:"available"`
	}
	type template struct {
		Name     string   `json:"name"`
		Profiles []string `json:"profiles"`
		Default  []string `json:"default_for"`
		Tools    []grant  `json:"tools"`
	}
	running := c.d.Servers.Servers()
	tools := []ToolView{}
	for _, alias := range sortedKeys(running) {
		tools = append(tools, toolViews(running[alias])...)
	}
	snap := c.d.Snapshot()
	if snap == nil {
		writeJSON(w, http.StatusOK, map[string]any{"policy_revision": "", "templates": []template{}, "tools": tools})
		return
	}
	byName := map[string]*template{}
	for pname, p := range snap.Profiles {
		for _, tn := range p.Templates {
			t := byName[tn]
			if t == nil {
				t = &template{Name: tn, Profiles: []string{}, Default: []string{}, Tools: []grant{}}
				byName[tn] = t
			}
			t.Profiles = append(t.Profiles, pname)
			if p.DefaultTemplate == tn {
				t.Default = append(t.Default, pname)
			}
		}
	}
	filter := r.URL.Query().Get("template")
	out := []template{}
	for _, name := range sortedKeys(byName) {
		if filter != "" && name != filter {
			continue
		}
		t := byName[name]
		sort.Strings(t.Profiles)
		sort.Strings(t.Default)
		for _, g := range snap.Grants(name) {
			s := running[g.Server]
			avail := false
			if s != nil {
				for _, bt := range s.Tools {
					if bt.Name == g.Tool {
						avail = true
						break
					}
				}
			}
			gr := grant{PublicName: backend.PublicName(g.Server, g.Tool), Server: g.Server, Tool: g.Tool, Available: avail, Filters: []string{}}
			if g.Rule != nil {
				gr.RuleID, gr.Approval, gr.Filters = g.Rule.ID, g.Rule.Approval, append(gr.Filters, g.Rule.Filters...)
			}
			t.Tools = append(t.Tools, gr)
		}
		out = append(out, *t)
	}
	if filter != "" && len(out) == 0 {
		writeError(w, http.StatusNotFound, "not_found", "the active policy has no such template")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy_revision": snap.Revision, "templates": out, "tools": tools})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
