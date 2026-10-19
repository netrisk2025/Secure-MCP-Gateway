package graph

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Fake is an in-memory Backend for tests. It interprets each catalog
// operation by its ID with the same semantics as the Neo4j template, so the
// Data Access Service, the mirror and the control API routes can be tested
// without a database. Integration tests (SMCP_NEO4J_URL) run the same
// scenarios against Neo4j.
type Fake struct {
	mu       sync.Mutex
	nodes    map[string]map[string]map[string]any // label -> id -> props
	rels     map[fakeRel]bool
	schema   []string
	err      error
	block    chan struct{}
	writes   int
	reads    int
	Settings map[string]string
	Heap     map[string]int64
}

type fakeRel struct{ typ, fromLabel, from, toLabel, to string }

// NewFake returns an empty fake graph with hardened default settings.
func NewFake() *Fake {
	return &Fake{nodes: map[string]map[string]map[string]any{}, rels: map[fakeRel]bool{},
		Settings: map[string]string{
			"server.http.enabled": "false", "server.https.enabled": "false", "dbms.usage_report.enabled": "false",
			"dbms.security.allow_csv_import_from_file_urls": "false", "dbms.security.procedures.unrestricted": "",
			"dbms.security.procedures.allowlist": "", "server.bolt.listen_address": "127.0.0.1:7687",
			"server.default_listen_address": "127.0.0.1", "server.memory.heap.max_size": "1.00GiB",
			"server.memory.pagecache.size": "512.00MiB",
		},
		Heap: map[string]int64{"used": 100 << 20, "committed": 512 << 20, "max": 1 << 30}}
}

// Fail makes every later statement fail with err (nil restores).
func (f *Fake) Fail(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }

// Block makes every later statement wait until Unblock or its context
// ends, simulating a hung database.
func (f *Fake) Block() { f.mu.Lock(); f.block = make(chan struct{}); f.mu.Unlock() }

// Unblock releases blocked statements.
func (f *Fake) Unblock() {
	f.mu.Lock()
	if f.block != nil {
		close(f.block)
		f.block = nil
	}
	f.mu.Unlock()
}

// Writes reports how many write transactions committed.
func (f *Fake) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }

// Node returns a copy of a node's properties, or nil.
func (f *Fake) Node(label, id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[label][id]
	if n == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range n {
		out[k] = v
	}
	return out
}

// Count returns the number of nodes with label.
func (f *Fake) Count(label string) int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.nodes[label]) }

// HasRel reports whether the relationship exists.
func (f *Fake) HasRel(fromLabel, from, typ, toLabel, to string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rels[fakeRel{typ, fromLabel, from, toLabel, to}]
}

// RelCount returns the number of relationships.
func (f *Fake) RelCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.rels) }

// Schema returns the schema statements applied.
func (f *Fake) Schema() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.schema...)
}

func (f *Fake) gate(ctx context.Context) error {
	f.mu.Lock()
	b, err := f.block, f.err
	f.mu.Unlock()
	if b != nil {
		select {
		case <-b:
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
		}
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}

// Write implements Backend. Statements apply atomically: on error none of
// them remain.
func (f *Fake) Write(ctx context.Context, stmts []Statement) ([][]Row, error) {
	if err := f.gate(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	snapNodes, snapRels, snapSchema := f.clone()
	out := make([][]Row, len(stmts))
	for i, st := range stmts {
		if st.Op.mode != ModeWrite {
			f.nodes, f.rels, f.schema = snapNodes, snapRels, snapSchema
			return nil, fmt.Errorf("fake: %s is not a write", st.Op.id)
		}
		rows, err := f.apply(st)
		if err != nil {
			f.nodes, f.rels, f.schema = snapNodes, snapRels, snapSchema
			return nil, err
		}
		out[i] = rows
	}
	f.writes++
	return out, nil
}

// Read implements Backend.
func (f *Fake) Read(ctx context.Context, st Statement) ([]Row, error) {
	if err := f.gate(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if st.Op.mode != ModeRead {
		return nil, fmt.Errorf("fake: %s is not a read", st.Op.id)
	}
	return f.apply(st)
}

// Close implements Backend.
func (f *Fake) Close(context.Context) error { return nil }

func (f *Fake) clone() (map[string]map[string]map[string]any, map[fakeRel]bool, []string) {
	n := make(map[string]map[string]map[string]any, len(f.nodes))
	for l, m := range f.nodes {
		mm := make(map[string]map[string]any, len(m))
		for id, p := range m {
			pp := make(map[string]any, len(p))
			for k, v := range p {
				pp[k] = v
			}
			mm[id] = pp
		}
		n[l] = mm
	}
	r := make(map[fakeRel]bool, len(f.rels))
	for k := range f.rels {
		r[k] = true
	}
	return n, r, append([]string(nil), f.schema...)
}

func (f *Fake) node(label, id string) map[string]any {
	m := f.nodes[label]
	if m == nil {
		m = map[string]map[string]any{}
		f.nodes[label] = m
	}
	n := m[id]
	if n == nil {
		n = map[string]any{"id": id}
		m[id] = n
	}
	return n
}

func i64(v any) (int64, bool) { n, ok := v.(int64); return n, ok }

func (f *Fake) apply(st Statement) ([]Row, error) {
	id := st.Op.id
	p := st.Params
	parts := strings.Split(id, ".")
	switch {
	case parts[0] == "migration":
		f.schema = append(f.schema, st.Op.text)
		return nil, nil
	case parts[0] == "upsert":
		for _, row := range p["rows"].([]map[string]any) {
			n := f.node(parts[1], row["id"].(string))
			ts, _ := i64(row["ts"])
			if fs, ok := i64(n["firstSeen"]); !ok || ts < fs {
				n["firstSeen"] = ts
			}
			ls, ok := i64(n["lastSeen"])
			if !ok {
				ls = -1
			}
			if ls <= ts {
				for k, v := range row["props"].(map[string]any) {
					n[k] = v
				}
				n["lastSeen"] = ts
			}
		}
		return nil, nil
	case parts[0] == "link":
		for _, row := range p["rows"].([]map[string]any) {
			from, to := row["from"].(string), row["to"].(string)
			f.node(parts[1], from)
			f.node(parts[3], to)
			f.rels[fakeRel{parts[2], parts[1], from, parts[3], to}] = true
		}
		return nil, nil
	}
	switch id {
	case "ping":
		return []Row{{"ok": int64(1)}}, nil
	case "checkpoint.get", "schema.get":
		cid := "schema"
		if id == "checkpoint.get" {
			cid = p["id"].(string)
		}
		n := f.nodes["Checkpoint"][cid]
		if n == nil {
			return nil, nil
		}
		return []Row{{"segment": n["segment"], "events": n["events"], "updated": n["updated"], "version": n["version"]}}, nil
	case "checkpoint.set":
		n := f.node("Checkpoint", p["id"].(string))
		n["segment"], n["events"], n["updated"] = p["segment"], p["events"], p["updated"]
		return nil, nil
	case "checkpoint.delete":
		f.deleteNode("Checkpoint", p["id"].(string))
		return nil, nil
	case "schema.set":
		n := f.node("Checkpoint", "schema")
		n["version"], n["updated"] = p["version"], p["updated"]
		return nil, nil
	case "status.counts":
		c := func(l string) int64 { return int64(len(f.nodes[l])) }
		return []Row{{"auditEvents": c("AuditEvent"), "sessions": c("Session"), "principals": c("Principal"), "invocations": c("Invocation"),
			"decisions": c("Decision"), "policyRevisions": c("PolicyRevision"), "serverRevisions": c("ServerRevision"),
			"toolRevisions": c("ToolRevision"), "approvals": c("Approval")}}, nil
	case "status.settings":
		var rows []Row
		for _, name := range p["names"].([]string) {
			if v, ok := f.Settings[name]; ok {
				rows = append(rows, Row{"name": name, "value": v})
			}
		}
		return rows, nil
	case "status.heap":
		return []Row{{"used": f.Heap["used"], "committed": f.Heap["committed"], "max": f.Heap["max"]}}, nil
	case "status.schema":
		var rows []Row
		for _, s := range f.schema {
			fl := strings.Fields(s)
			if len(fl) > 2 && fl[0] == "CREATE" {
				kind := map[string]string{"CONSTRAINT": "constraint", "INDEX": "index"}[fl[1]]
				rows = append(rows, Row{"kind": kind, "name": fl[2], "state": "ONLINE"})
			}
		}
		return rows, nil
	case "wipe.mirror":
		limit, _ := i64(p["limit"])
		var n int64
		for _, l := range mirrorLabels {
			for nid := range f.nodes[l] {
				if n >= limit {
					break
				}
				f.deleteNode(l, nid)
				n++
			}
		}
		return []Row{{"deleted": n}}, nil
	}
	if parts[0] == "retention" {
		return f.retention(parts[1], p), nil
	}
	if parts[0] == "neighborhood" {
		return f.neighborhood(parts[1], p), nil
	}
	if id == "event.path" {
		return f.eventPath(p), nil
	}
	if parts[0] == "query" {
		return f.query(parts[1], p), nil
	}
	return nil, fmt.Errorf("fake: no semantics for %s", id)
}

func (f *Fake) deleteNode(label, id string) {
	delete(f.nodes[label], id)
	for r := range f.rels {
		if (r.fromLabel == label && r.from == id) || (r.toLabel == label && r.to == id) {
			delete(f.rels, r)
		}
	}
}

func (f *Fake) hasIncoming(label, id, typ, fromLabel string) bool {
	for r := range f.rels {
		if r.toLabel == label && r.to == id && (typ == "" || r.typ == typ) && (fromLabel == "" || r.fromLabel == fromLabel) {
			return true
		}
	}
	return false
}

func (f *Fake) retention(label string, p map[string]any) []Row {
	cutoff, _ := i64(p["cutoff"])
	limit, _ := i64(p["limit"])
	key := "lastSeen"
	if label == "AuditEvent" {
		key = "ts"
	}
	var n int64
	for _, nid := range sortedIDs(f.nodes[label]) {
		if n >= limit {
			break
		}
		v, ok := i64(f.nodes[label][nid][key])
		if !ok || v >= cutoff {
			continue
		}
		switch label {
		case "Decision":
			if f.hasIncoming(label, nid, "FOR_DECISION", "AuditEvent") {
				continue
			}
		case "Invocation":
			if f.hasIncoming(label, nid, "FOR_INVOCATION", "") {
				continue
			}
		case "Session":
			if f.hasIncoming(label, nid, "IN_SESSION", "") {
				continue
			}
		}
		f.deleteNode(label, nid)
		n++
	}
	return []Row{{"deleted": n}}
}

func sortedIDs(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (f *Fake) withLabels(label string, props map[string]any) map[string]any {
	out := map[string]any{"labels": []any{label}}
	for k, v := range props {
		out[k] = v
	}
	return out
}

func copyProps(props map[string]any) map[string]any {
	if props == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range props {
		out[k] = v
	}
	return out
}

func (f *Fake) neighborhood(label string, p map[string]any) []Row {
	id := p["id"].(string)
	limit, _ := i64(p["limit"])
	n := f.nodes[label][id]
	if n == nil {
		return nil
	}
	type link struct {
		row  map[string]any
		seen int64
		id   string
	}
	var links []link
	var degree int64
	for r := range f.rels {
		var ol, oid string
		switch {
		case r.fromLabel == label && r.from == id:
			ol, oid = r.toLabel, r.to
		case r.toLabel == label && r.to == id:
			ol, oid = r.fromLabel, r.from
		default:
			continue
		}
		degree++
		m := f.nodes[ol][oid]
		seen, _ := i64(m["lastSeen"])
		links = append(links, link{map[string]any{"type": r.typ, "from": r.from, "to": r.to, "node": f.withLabels(ol, m)}, seen, oid})
	}
	sort.Slice(links, func(i, k int) bool {
		if links[i].seen != links[k].seen {
			return links[i].seen > links[k].seen
		}
		return links[i].id < links[k].id
	})
	if int64(len(links)) > limit {
		links = links[:limit]
	}
	out := make([]any, len(links))
	for i, l := range links {
		out[i] = l.row
	}
	return []Row{{"node": f.withLabels(label, n), "links": out, "degree": degree}}
}

func (f *Fake) out(label, id, typ, toLabel string) map[string]any {
	for r := range f.rels {
		if r.fromLabel == label && r.from == id && r.typ == typ && r.toLabel == toLabel {
			return copyProps(f.nodes[toLabel][r.to])
		}
	}
	return nil
}

func (f *Fake) eventPath(p map[string]any) []Row {
	id := p["id"].(string)
	limit, _ := i64(p["limit"])
	e := f.nodes["AuditEvent"][id]
	if e == nil {
		return nil
	}
	row := Row{"event": copyProps(e), "decision": f.out("AuditEvent", id, "FOR_DECISION", "Decision"),
		"invocation": f.out("AuditEvent", id, "FOR_INVOCATION", "Invocation"), "session": f.out("AuditEvent", id, "IN_SESSION", "Session"),
		"serverRevision": f.out("AuditEvent", id, "OBSERVED_FROM", "ServerRevision"), "policyRevision": f.out("AuditEvent", id, "RECORDED_UNDER", "PolicyRevision")}
	row["principal"], row["toolRevision"] = map[string]any(nil), map[string]any(nil)
	if s, _ := row["session"].(map[string]any); s != nil {
		row["principal"] = f.out("Session", s["id"].(string), "OF_PRINCIPAL", "Principal")
	}
	if i, _ := row["invocation"].(map[string]any); i != nil {
		row["toolRevision"] = f.out("Invocation", i["id"].(string), "INVOKED", "ToolRevision")
	}
	rules := []any{}
	row["auditProfile"] = map[string]any(nil)
	if d, _ := row["decision"].(map[string]any); d != nil {
		did := d["id"].(string)
		var ids []string
		for r := range f.rels {
			switch {
			case r.fromLabel == "Decision" && r.from == did && r.typ == "DECIDED_BY" && r.toLabel == "RuleRevision":
				ids = append(ids, r.to)
			case r.fromLabel == "AuditEvent" && r.typ == "FOR_DECISION" && r.toLabel == "Decision" && r.to == did:
				if ap := f.out("AuditEvent", r.from, "RECORDED_UNDER", "PolicyObject"); ap != nil {
					row["auditProfile"] = ap
				}
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			rules = append(rules, copyProps(f.nodes["RuleRevision"][id]))
		}
	}
	row["decisiveRules"] = rules
	var phases []map[string]any
	if corr, ok := e["correlationId"].(string); ok {
		for _, o := range f.nodes["AuditEvent"] {
			if o["correlationId"] == corr {
				phases = append(phases, copyProps(o))
			}
		}
	}
	sortByTS(phases)
	if int64(len(phases)) > limit {
		phases = phases[:limit]
	}
	ph := make([]any, len(phases))
	for i, x := range phases {
		ph[i] = x
	}
	row["phases"] = ph
	return []Row{row}
}

func sortByTS(l []map[string]any) {
	sort.Slice(l, func(i, k int) bool {
		a, _ := i64(l[i]["ts"])
		b, _ := i64(l[k]["ts"])
		if a != b {
			return a < b
		}
		return fmt.Sprint(l[i]["id"]) < fmt.Sprint(l[k]["id"])
	})
}

func (f *Fake) countIn(label, id, typ, fromLabel string) int64 {
	var n int64
	for r := range f.rels {
		if r.toLabel == label && r.to == id && r.typ == typ && r.fromLabel == fromLabel {
			n++
		}
	}
	return n
}

func (f *Fake) query(name string, p map[string]any) []Row {
	limit, _ := i64(p["limit"])
	var rows []Row
	byLastSeen := func(label string, mk func(id string, n map[string]any) Row) {
		ids := sortedIDs(f.nodes[label])
		sort.SliceStable(ids, func(i, k int) bool {
			a, _ := i64(f.nodes[label][ids[i]]["lastSeen"])
			b, _ := i64(f.nodes[label][ids[k]]["lastSeen"])
			return a > b
		})
		for _, id := range ids {
			if r := mk(id, f.nodes[label][id]); r != nil {
				rows = append(rows, r)
			}
		}
	}
	switch name {
	case "recent_sessions":
		byLastSeen("Session", func(id string, n map[string]any) Row {
			var principal any
			if pr := f.out("Session", id, "OF_PRINCIPAL", "Principal"); pr != nil {
				principal = pr["id"]
			}
			return Row{"session": id, "principal": principal, "state": n["state"], "firstSeen": n["firstSeen"], "lastSeen": n["lastSeen"],
				"calls": f.countIn("Session", id, "IN_SESSION", "Invocation")}
		})
	case "recent_denials":
		byLastSeen("Decision", func(id string, n map[string]any) Row {
			if n["outcome"] != "deny" {
				return nil
			}
			return Row{"decision": id, "ts": n["ts"], "reasonCode": n["reasonCode"], "session": n["sessionId"], "correlationId": n["correlationId"], "policyRevision": n["revisionId"]}
		})
	case "tool_usage":
		for _, id := range sortedIDs(f.nodes["ToolRevision"]) {
			rows = append(rows, Row{"toolRevision": id, "calls": f.countIn("ToolRevision", id, "INVOKED", "Invocation"), "lastSeen": f.nodes["ToolRevision"][id]["lastSeen"]})
		}
		sort.SliceStable(rows, func(i, k int) bool { return rows[i]["calls"].(int64) > rows[k]["calls"].(int64) })
	case "call_timeline":
		var evs []map[string]any
		for _, e := range f.nodes["AuditEvent"] {
			if e["correlationId"] == p["correlationId"] {
				evs = append(evs, e)
			}
		}
		sortByTS(evs)
		for _, e := range evs {
			rows = append(rows, Row{"event": e["id"], "ts": e["ts"], "class": e["class"], "phase": e["phase"], "origin": e["origin"], "outcome": e["outcome"], "reasonCode": e["reasonCode"]})
		}
	case "principal_activity":
		byLastSeen("Principal", func(id string, n map[string]any) Row {
			var calls int64
			for r := range f.rels {
				if r.typ == "OF_PRINCIPAL" && r.to == id {
					calls += f.countIn("Session", r.from, "IN_SESSION", "Invocation")
				}
			}
			return Row{"principal": id, "sessions": f.countIn("Principal", id, "OF_PRINCIPAL", "Session"), "calls": calls, "lastSeen": n["lastSeen"]}
		})
	case "policy_revisions":
		byLastSeen("PolicyRevision", func(id string, n map[string]any) Row {
			return Row{"policyRevision": id, "activatedAt": n["activatedAt"], "decisions": f.countIn("PolicyRevision", id, "EVALUATED_UNDER", "Decision"), "lastSeen": n["lastSeen"]}
		})
	case "approvals":
		byLastSeen("Approval", func(id string, n map[string]any) Row {
			return Row{"approval": id, "state": n["state"], "tool": n["publicName"], "session": n["sessionId"], "lastSeen": n["lastSeen"]}
		})
	}
	if int64(len(rows)) > limit {
		rows = rows[:limit]
	}
	return rows
}
