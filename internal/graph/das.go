package graph

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DAS is the Data Access Service (E-26) for the graph engine: the only
// holder of the database connection, exposing typed operations each mapped
// to one fixed template of the verified catalog (FR-9.3, SR-1.13-1).
type DAS struct {
	b   Backend
	cat *Catalog
	now func() time.Time
}

// NewDAS wraps a backend with the verified catalog.
func NewDAS(b Backend, cat *Catalog, now func() time.Time) *DAS {
	if cat == nil {
		cat = DefaultCatalog()
	}
	if now == nil {
		now = time.Now
	}
	return &DAS{b: b, cat: cat, now: now}
}

// Catalog returns the catalog in use.
func (d *DAS) Catalog() *Catalog { return d.cat }

func (d *DAS) stmt(id string, params map[string]any) (Statement, error) {
	op, err := d.cat.Op(id)
	if err != nil {
		return Statement{}, err
	}
	if params == nil {
		params = map[string]any{}
	}
	if err := op.Validate(params); err != nil {
		return Statement{}, err
	}
	return Statement{Op: op, Params: params}, nil
}

func (d *DAS) read(ctx context.Context, id string, params map[string]any) ([]Row, error) {
	st, err := d.stmt(id, params)
	if err != nil {
		return nil, err
	}
	if st.Op.mode != ModeRead {
		return nil, fmt.Errorf("%w: %s is a write operation", ErrUnknownOp, id)
	}
	return d.b.Read(ctx, st)
}

func (d *DAS) write(ctx context.Context, stmts ...Statement) ([][]Row, error) {
	for _, st := range stmts {
		if st.Op.mode != ModeWrite {
			return nil, fmt.Errorf("%w: %s is a read operation", ErrUnknownOp, st.Op.id)
		}
	}
	return d.b.Write(ctx, stmts)
}

// Ping checks the connection.
func (d *DAS) Ping(ctx context.Context) error {
	_, err := d.read(ctx, "ping", nil)
	return err
}

// SchemaVersion reads the applied schema version (0 for an empty database).
func (d *DAS) SchemaVersion(ctx context.Context) (int, error) {
	rows, err := d.read(ctx, "schema.get", nil)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	v, _ := rows[0]["version"].(int64)
	return int(v), nil
}

// Migrate applies the ordered migrations newer than the database's schema
// version and records each version (FR-9.2). It refuses a database whose
// version is newer than this release supports. It returns the version found
// and the version reached.
func (d *DAS) Migrate(ctx context.Context) (from, to int, err error) {
	from, err = d.SchemaVersion(ctx)
	if err != nil {
		return 0, 0, err
	}
	if from > d.cat.SchemaVersion() {
		return from, from, fmt.Errorf("%w: database schema %d, release supports %d", ErrSchemaTooNew, from, d.cat.SchemaVersion())
	}
	to = from
	for _, m := range d.cat.Migrations() {
		if m.Version <= from {
			continue
		}
		// Schema statements cannot share a transaction with data writes,
		// so each runs alone; all are idempotent (IF NOT EXISTS).
		for _, op := range m.Ops {
			if err := d.migrateOp(ctx, op); err != nil {
				return from, to, fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
			}
		}
		st, err := d.stmt("schema.set", map[string]any{"version": int64(m.Version), "updated": d.now().UnixNano()})
		if err != nil {
			return from, to, err
		}
		if _, err := d.write(ctx, st); err != nil {
			return from, to, err
		}
		to = m.Version
	}
	return from, to, nil
}

// constraintOp matches a migration's uniqueness constraint statement.
var constraintOp = regexp.MustCompile(`^\s*CREATE CONSTRAINT (smcp_[a-z0-9_]+) IF NOT EXISTS `)

// migrateOp runs one schema statement. A migration interrupted while the
// engine built a constraint's backing index (the Gateway stopped during
// its first start) can leave that index without its constraint; CREATE
// CONSTRAINT ... IF NOT EXISTS then fails on the index name and the
// database could never be migrated. The orphaned index, which carries the
// constraint's own name, is dropped and the statement run again.
func (d *DAS) migrateOp(ctx context.Context, op *Op) error {
	_, err := d.write(ctx, Statement{Op: op, Params: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "IndexWithNameAlreadyExists") {
		return err
	}
	m := constraintOp.FindStringSubmatch(op.text)
	if m == nil {
		return err
	}
	drop := &Op{id: "schema.drop_orphan_index", mode: ModeWrite, params: map[string]ParamType{}, text: "DROP INDEX " + m[1] + " IF EXISTS"}
	if _, derr := d.write(ctx, Statement{Op: drop, Params: map[string]any{}}); derr != nil {
		return fmt.Errorf("%w (dropping the orphaned index %s: %w)", err, m[1], derr)
	}
	_, err = d.write(ctx, Statement{Op: op, Params: map[string]any{}})
	return err
}

// SchemaObject is one constraint or index of the deployed schema.
type SchemaObject struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	State string `json:"state"`
}

// SchemaObjects lists the deployed constraints and range indexes.
func (d *DAS) SchemaObjects(ctx context.Context) ([]SchemaObject, error) {
	rows, err := d.read(ctx, "status.schema", nil)
	if err != nil {
		return nil, err
	}
	out := make([]SchemaObject, 0, len(rows))
	for _, r := range rows {
		k, _ := r["kind"].(string)
		n, _ := r["name"].(string)
		s, _ := r["state"].(string)
		out = append(out, SchemaObject{Kind: k, Name: n, State: s})
	}
	sort.Slice(out, func(i, k int) bool { return out[i].Name < out[k].Name })
	return out, nil
}

// validRow checks one projection node against the label allowlist.
func validRow(n nodeRow) error {
	allowed, ok := labelProps[n.label]
	if !ok {
		return fmt.Errorf("%w: label %q is not mirrored", ErrBadParameter, n.label)
	}
	if n.id == "" || len(n.id) > MaxStringParam {
		return fmt.Errorf("%w: %s id", ErrBadParameter, n.label)
	}
	for k, v := range n.props {
		if !allowed[k] {
			return fmt.Errorf("%w: %s.%s is not an allowed property", ErrBadParameter, n.label, k)
		}
		switch t := v.(type) {
		case string:
			if len(t) > maxPropString {
				return fmt.Errorf("%w: %s.%s too long", ErrBadParameter, n.label, k)
			}
		case int64, bool:
		default:
			return fmt.Errorf("%w: %s.%s has type %T", ErrBadParameter, n.label, k, v)
		}
	}
	return nil
}

// applyStatements turns a projection into catalog statements: node upserts
// grouped by label in event order, then links grouped by type.
func (d *DAS) applyStatements(p *projection) ([]Statement, error) {
	byLabel := map[string][]map[string]any{}
	var labels []string
	for _, n := range p.nodes {
		if err := validRow(n); err != nil {
			return nil, err
		}
		if _, ok := byLabel[n.label]; !ok {
			labels = append(labels, n.label)
		}
		byLabel[n.label] = append(byLabel[n.label], map[string]any{"id": n.id, "ts": n.ts, "props": n.props})
	}
	byLink := map[string][]map[string]any{}
	var links []string
	for _, l := range p.links {
		if _, ok := byLink[l.op]; !ok {
			links = append(links, l.op)
		}
		byLink[l.op] = append(byLink[l.op], map[string]any{"from": l.from, "to": l.to})
	}
	var stmts []Statement
	add := func(id string, rows []map[string]any) error {
		for len(rows) > 0 {
			n := min(len(rows), MaxRows)
			st, err := d.stmt(id, map[string]any{"rows": rows[:n]})
			if err != nil {
				return err
			}
			stmts = append(stmts, st)
			rows = rows[n:]
		}
		return nil
	}
	for _, l := range labels {
		if err := add("upsert."+l, byLabel[l]); err != nil {
			return nil, err
		}
	}
	for _, l := range links {
		if err := add(l, byLink[l]); err != nil {
			return nil, err
		}
	}
	return stmts, nil
}

// apply writes a projection in one transaction.
func (d *DAS) apply(ctx context.Context, p *projection) error {
	if len(p.nodes) == 0 {
		return nil
	}
	stmts, err := d.applyStatements(p)
	if err != nil {
		return err
	}
	_, err = d.write(ctx, stmts...)
	return err
}

// Checkpoint is the mirror's position in the journal: every segment before
// Segment has been applied.
type Checkpoint struct {
	Segment int   `json:"segment"`
	Events  int64 `json:"events"`
	Updated int64 `json:"updated"`
}

const mirrorCheckpoint = "journal-mirror"

// GetCheckpoint reads the mirror checkpoint (zero when absent).
func (d *DAS) GetCheckpoint(ctx context.Context) (Checkpoint, error) {
	rows, err := d.read(ctx, "checkpoint.get", map[string]any{"id": mirrorCheckpoint})
	if err != nil || len(rows) == 0 {
		return Checkpoint{}, err
	}
	seg, _ := rows[0]["segment"].(int64)
	ev, _ := rows[0]["events"].(int64)
	up, _ := rows[0]["updated"].(int64)
	return Checkpoint{Segment: int(seg), Events: ev, Updated: up}, nil
}

// SetCheckpoint records the mirror checkpoint.
func (d *DAS) SetCheckpoint(ctx context.Context, c Checkpoint) error {
	st, err := d.stmt("checkpoint.set", map[string]any{"id": mirrorCheckpoint, "segment": int64(c.Segment), "events": c.Events, "updated": d.now().UnixNano()})
	if err != nil {
		return err
	}
	_, err = d.write(ctx, st)
	return err
}

// batchDelete runs a bounded delete operation until it deletes fewer rows
// than the batch limit, one transaction per batch.
func (d *DAS) batchDelete(ctx context.Context, id string, params map[string]any, limit int64) (int64, error) {
	var total int64
	for {
		p := map[string]any{"limit": limit}
		for k, v := range params {
			p[k] = v
		}
		st, err := d.stmt(id, p)
		if err != nil {
			return total, err
		}
		res, err := d.write(ctx, st)
		if err != nil {
			return total, err
		}
		var n int64
		if len(res) == 1 && len(res[0]) == 1 {
			n, _ = res[0][0]["deleted"].(int64)
		}
		total += n
		if n < limit {
			return total, nil
		}
	}
}

// Wipe removes every mirrored node and the mirror checkpoint. Behavior
// model and catalog labels are not touched.
func (d *DAS) Wipe(ctx context.Context) (int64, error) {
	n, err := d.batchDelete(ctx, "wipe.mirror", nil, 5000)
	if err != nil {
		return n, err
	}
	st, err := d.stmt("checkpoint.delete", map[string]any{"id": mirrorCheckpoint})
	if err != nil {
		return n, err
	}
	_, err = d.write(ctx, st)
	return n, err
}

// retentionOrder deletes events first, then the records only they
// referenced. Principals and policy, server and tool revisions are kept:
// they are few and every unexpired record may reference them (SR-6.14-1).
var retentionOrder = []string{"AuditEvent", "Decision", "Approval", "Invocation", "Session"}

// Retain deletes mirrored records older than cutoff in bounded batches and
// returns the number deleted per label.
func (d *DAS) Retain(ctx context.Context, cutoff time.Time, batch int64) (map[string]int64, error) {
	out := map[string]int64{}
	for _, l := range retentionOrder {
		n, err := d.batchDelete(ctx, "retention."+l, map[string]any{"cutoff": cutoff.UnixNano()}, batch)
		out[l] = n
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// Counts returns the number of mirrored nodes per kind.
func (d *DAS) Counts(ctx context.Context) (map[string]int64, error) {
	rows, err := d.read(ctx, "status.counts", nil)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	out := map[string]int64{}
	for k, v := range rows[0] {
		n, _ := v.(int64)
		out[k] = n
	}
	return out, nil
}

// Settings returns the named server settings.
func (d *DAS) Settings(ctx context.Context, names []string) (map[string]string, error) {
	rows, err := d.read(ctx, "status.settings", map[string]any{"names": names})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		n, _ := r["name"].(string)
		v, _ := r["value"].(string)
		out[n] = v
	}
	return out, nil
}

// Heap is the graph engine's JVM heap use in bytes.
type Heap struct {
	Used      int64 `json:"used"`
	Committed int64 `json:"committed"`
	Max       int64 `json:"max"`
}

// HeapUse reads the engine's heap use.
func (d *DAS) HeapUse(ctx context.Context) (Heap, error) {
	rows, err := d.read(ctx, "status.heap", nil)
	if err != nil {
		return Heap{}, err
	}
	if len(rows) == 0 {
		return Heap{}, errors.New("graph: no heap data")
	}
	u, _ := rows[0]["used"].(int64)
	c, _ := rows[0]["committed"].(int64)
	m, _ := rows[0]["max"].(int64)
	return Heap{Used: u, Committed: c, Max: m}, nil
}

// NeighborhoodLabels are the labels a neighborhood query may start from.
var NeighborhoodLabels = []string{"AuditEvent", "Session", "Principal", "Invocation", "Decision", "PolicyRevision", "ServerRevision", "ToolRevision", "Approval"}

// GraphNode is a node of a bounded neighborhood.
type GraphNode struct {
	ID     string         `json:"id"`
	Labels []string       `json:"labels"`
	Props  map[string]any `json:"properties"`
}

// GraphEdge is a relationship of a bounded neighborhood.
type GraphEdge struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Neighborhood is a node, its neighbors up to a bound, and whether the
// bound cut neighbors off.
type Neighborhood struct {
	Node      GraphNode   `json:"node"`
	Neighbors []GraphNode `json:"neighbors"`
	Edges     []GraphEdge `json:"edges"`
	Degree    int64       `json:"degree"`
	Truncated bool        `json:"truncated"`
}

func toNode(v any) GraphNode {
	m, _ := v.(map[string]any)
	g := GraphNode{Props: map[string]any{}}
	for k, x := range m {
		switch k {
		case "id":
			g.ID, _ = x.(string)
		case "labels":
			l, _ := x.([]any)
			for _, s := range l {
				if str, ok := s.(string); ok {
					g.Labels = append(g.Labels, str)
				}
			}
		default:
			g.Props[k] = x
		}
	}
	return g
}

// Neighborhood returns the bounded one-hop neighborhood of the node with
// the given label and id. The label selects one of the fixed templates;
// any other label is refused.
func (d *DAS) Neighborhood(ctx context.Context, label, id string, limit int) (*Neighborhood, error) {
	if !contains(NeighborhoodLabels, label) {
		return nil, fmt.Errorf("%w: label %q", ErrBadParameter, label)
	}
	rows, err := d.read(ctx, "neighborhood."+label, map[string]any{"id": id, "limit": int64(clampLimit(limit))})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	nb := &Neighborhood{Node: toNode(rows[0]["node"]), Neighbors: []GraphNode{}, Edges: []GraphEdge{}}
	nb.Degree, _ = rows[0]["degree"].(int64)
	links, _ := rows[0]["links"].([]any)
	seen := map[string]bool{}
	for _, l := range links {
		m, _ := l.(map[string]any)
		e := GraphEdge{}
		e.Type, _ = m["type"].(string)
		e.From, _ = m["from"].(string)
		e.To, _ = m["to"].(string)
		nb.Edges = append(nb.Edges, e)
		n := toNode(m["node"])
		key := fmt.Sprint(n.Labels, n.ID)
		if !seen[key] {
			seen[key] = true
			nb.Neighbors = append(nb.Neighbors, n)
		}
	}
	nb.Truncated = int64(len(nb.Edges)) < nb.Degree
	return nb, nil
}

// EventPath is the investigation path of one audit event (G-14): its
// decision, invocation, session, principal, server, tool and policy
// revisions, and the other phases of the same call.
type EventPath struct {
	Event          map[string]any `json:"event"`
	Decision       map[string]any `json:"decision"`
	Invocation     map[string]any `json:"invocation"`
	Session        map[string]any `json:"session"`
	Principal      map[string]any `json:"principal"`
	ServerRevision map[string]any `json:"serverRevision"`
	ToolRevision   map[string]any `json:"toolRevision"`
	PolicyRevision map[string]any `json:"policyRevision"`
	// DecisiveRules are the decision's decisive rule revisions and
	// AuditProfile the Audit Profile revision of its decision event
	// (SR-6.4-1).
	DecisiveRules []map[string]any `json:"decisiveRules"`
	AuditProfile  map[string]any   `json:"auditProfile"`
	Phases        []map[string]any `json:"phases"`
}

// EventPath returns the bounded investigation path of an audit event.
func (d *DAS) EventPath(ctx context.Context, id string, limit int) (*EventPath, error) {
	rows, err := d.read(ctx, "event.path", map[string]any{"id": id, "limit": int64(clampLimit(limit))})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	r := rows[0]
	m := func(k string) map[string]any { v, _ := r[k].(map[string]any); return v }
	p := &EventPath{Event: m("event"), Decision: m("decision"), Invocation: m("invocation"), Session: m("session"), Principal: m("principal"),
		ServerRevision: m("serverRevision"), ToolRevision: m("toolRevision"), PolicyRevision: m("policyRevision"),
		AuditProfile: m("auditProfile"), DecisiveRules: []map[string]any{}, Phases: []map[string]any{}}
	dr, _ := r["decisiveRules"].([]any)
	for _, x := range dr {
		if mm, ok := x.(map[string]any); ok {
			p.DecisiveRules = append(p.DecisiveRules, mm)
		}
	}
	ph, _ := r["phases"].([]any)
	for _, x := range ph {
		if mm, ok := x.(map[string]any); ok {
			p.Phases = append(p.Phases, mm)
		}
	}
	return p, nil
}

// CannedQuery is one read-only query of smcpctl graph query and the
// control API.
type CannedQuery struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Params      []string `json:"params"`
}

// CannedQueries lists the read-only canned queries.
var CannedQueries = []CannedQuery{
	{"recent_sessions", "sessions by last activity, with principal, state and call count", []string{"limit"}},
	{"recent_denials", "policy denials, newest first", []string{"limit"}},
	{"tool_usage", "tool revisions by number of calls", []string{"limit"}},
	{"call_timeline", "every evidence event of one call, in order", []string{"correlationId", "limit"}},
	{"principal_activity", "principals with session and call counts", []string{"limit"}},
	{"policy_revisions", "policy revisions with activation time and decision count", []string{"limit"}},
	{"approvals", "approvals by last change", []string{"limit"}},
}

var queryParam = regexp.MustCompile(`^[A-Za-z0-9._:@/+-]{1,256}$`)

// Query runs a canned read-only query.
func (d *DAS) Query(ctx context.Context, name string, params map[string]string, limit int) ([]Row, error) {
	var q *CannedQuery
	for i := range CannedQueries {
		if CannedQueries[i].Name == name {
			q = &CannedQueries[i]
		}
	}
	if q == nil {
		return nil, fmt.Errorf("%w: query %q", ErrUnknownOp, name)
	}
	p := map[string]any{"limit": int64(clampLimit(limit))}
	for k, v := range params {
		if !contains(q.Params, k) || k == "limit" {
			return nil, fmt.Errorf("%w: query %s does not take %q", ErrBadParameter, name, k)
		}
		if !queryParam.MatchString(v) {
			return nil, fmt.Errorf("%w: %s", ErrBadParameter, k)
		}
		p[k] = v
	}
	for _, k := range q.Params {
		if _, ok := p[k]; !ok {
			return nil, fmt.Errorf("%w: query %s needs %q", ErrBadParameter, name, k)
		}
	}
	rows, err := d.read(ctx, "query."+name, p)
	if rows == nil {
		rows = []Row{}
	}
	return rows, err
}

// DefaultLimit is the result bound when a caller gives none.
const DefaultLimit = 50

func clampLimit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	return min(n, MaxLimit)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
