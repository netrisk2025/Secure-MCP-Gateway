package research

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/baseline"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/observe"
	"github.com/ethan03805/secure-mcp-gateway/internal/obsstore"
)

// Formats.
const (
	Parquet = "parquet"
	CSV     = "csv"
	JSONL   = "jsonl"
	GraphML = "graphml"
)

// pseudonymized lists the record columns replaced by pseudonyms in every
// export, besides every S2 parameter (FR-10.33, SR-6-1).
var pseudonymized = map[string]bool{"principal_id": true, "session_id": true, "end_user_claim": true, "correlation_id": true}

// Request is a dataset export request.
type Request struct {
	CampaignID string    `json:"campaign_id,omitempty"`
	Format     string    `json:"format"`
	From       time.Time `json:"from,omitempty"`
	To         time.Time `json:"to,omitempty"`
	Scope      Scope     `json:"scope,omitempty"`
	Parameters []string  `json:"parameters,omitempty"`
	SnapshotID string    `json:"snapshot_id,omitempty"` // graphml: snapshot to export (default promoted)
	// Subgraph selects the GraphML export: "behavior-model" (default, the
	// baseline snapshot) or "audit" (the calls in scope with their
	// sessions, principals, tools and policy revisions).
	Subgraph string `json:"subgraph,omitempty"`
}

// GraphML subgraphs (FR-10.34).
const (
	SubgraphBehavior = "behavior-model"
	SubgraphAudit    = "audit"
)

// File is one exported file.
type File struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Manifest is the provenance manifest (FR-10.35).
type Manifest struct {
	DatasetID         string            `json:"dataset_id"`
	CreatedAt         time.Time         `json:"created_at"`
	CreatedBy         string            `json:"created_by"`
	Format            string            `json:"format"`
	Campaign          *Campaign         `json:"campaign,omitempty"`
	Filters           map[string]any    `json:"filters"`
	CatalogVersion    string            `json:"catalog_version"`
	PolicyRevisions   []string          `json:"policy_revisions"`
	BaselineSnapshots []string          `json:"baseline_snapshots"`
	TimeRange         map[string]any    `json:"time_range"`
	Rows              int64             `json:"rows"`
	Columns           []string          `json:"columns"`
	Pseudonymization  map[string]any    `json:"pseudonymization"`
	Files             []File            `json:"files"`
	Store             string            `json:"store_backend"`
	Extra             map[string]string `json:"notes,omitempty"`
}

// Exporter writes datasets.
type Exporter struct {
	Store     obsstore.Store
	Catalog   *observe.Catalog
	Campaigns *Campaigns
	Snapshots *baseline.SnapshotStore
	Dir       string // export directory (CP-46 exports/)
	KeyDir    string // per-dataset keys (E-22 key directory)
	Now       func() time.Time
}

// Errors.
var (
	ErrFormat      = errors.New("unsupported export format")
	ErrNoParquet   = errors.New("parquet export needs the DuckDB store backend (cgo build)")
	ErrRawGrant    = errors.New("S3 raw-payload parameters need a campaign with an approved raw_export_grant")
	ErrNotExported = errors.New("campaign is not completed or exported")
	ErrNoSnapshot  = errors.New("no baseline snapshot to export")
)

// Key returns a new per-dataset key and keeps it in KeyDir (0600).
func (x *Exporter) newKey(dataset string) ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(x.KeyDir, 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(filepath.Join(x.KeyDir, dataset+".key"), []byte(hex.EncodeToString(k)+"\n"), 0o600)
}

// Pseudonym is HMAC-SHA-256 of v under key, as "ps_" and 32 hex digits
// (CP-40).
func Pseudonym(key []byte, v string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(v))
	return "ps_" + hex.EncodeToString(m.Sum(nil)[:16])
}

// pseudonymize replaces every string inside v (keys included).
func pseudonymize(key []byte, v any) any {
	switch x := v.(type) {
	case string:
		if x == "" {
			return x
		}
		// JSON text of an object or array column: pseudonymize inside it.
		if (strings.HasPrefix(x, "{") || strings.HasPrefix(x, "[")) && json.Valid([]byte(x)) {
			var inner any
			if json.Unmarshal([]byte(x), &inner) == nil {
				b, _ := json.Marshal(pseudonymize(key, inner))
				return string(b)
			}
		}
		return Pseudonym(key, x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = pseudonymize(key, e)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[Pseudonym(key, k)] = pseudonymize(key, e)
		}
		return out
	}
	return v
}

// columnType maps a catalog data type to a store column type.
func columnType(p observe.Param) string {
	switch p.DataType {
	case "integer":
		return obsstore.BigInt
	case "number":
		return obsstore.Double
	}
	return obsstore.Varchar
}

// safeName is an export ID or file name: no separators and no leading dot,
// so neither "." nor ".." can name a directory outside the export.
var safeName = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$`)

// Export extracts and writes a dataset. actor is recorded in the manifest.
func (x *Exporter) Export(req Request, actor string) (Manifest, error) {
	now := time.Now
	if x.Now != nil {
		now = x.Now
	}
	m := Manifest{DatasetID: ids.New(), CreatedAt: now().UTC(), CreatedBy: actor, Format: req.Format, CatalogVersion: x.Catalog.Version,
		Filters: map[string]any{}, PolicyRevisions: []string{}, BaselineSnapshots: []string{}, TimeRange: map[string]any{},
		Pseudonymization: map[string]any{"function": "HMAC-SHA-256", "key": "per dataset, " + filepath.Join("keys", "research", "<dataset_id>.key")},
		Store:            x.Store.Backend()}
	switch req.Format {
	case Parquet:
		if _, ok := x.Store.(obsstore.ParquetWriter); !ok {
			return m, ErrNoParquet
		}
	case CSV, JSONL:
	case GraphML:
		if req.Subgraph != "" && req.Subgraph != SubgraphBehavior && req.Subgraph != SubgraphAudit {
			return m, fmt.Errorf("%w: GraphML subgraph %q (behavior-model, audit)", ErrFormat, req.Subgraph)
		}
	default:
		return m, fmt.Errorf("%w: %q (parquet, csv, jsonl, graphml)", ErrFormat, req.Format)
	}
	raw := false
	scope := req.Scope
	from, to := req.From, req.To
	params := req.Parameters
	if req.CampaignID != "" {
		cp, err := x.Campaigns.Get(req.CampaignID)
		if err != nil {
			return m, err
		}
		if cp.State != Completed && cp.State != Exported && cp.State != Active {
			return m, fmt.Errorf("%w (state %s)", ErrNotExported, cp.State)
		}
		m.Campaign = &cp
		scope, from, to, raw = cp.Scope, cp.Start, cp.End, cp.RawExport
		if len(params) == 0 {
			params = cp.Parameters
		}
	}
	if len(params) == 0 {
		params = x.Catalog.DefaultParameters()
	}
	names, err := x.Catalog.Resolve(params)
	if err != nil {
		return m, err
	}
	for _, n := range names {
		if p, _ := x.Catalog.Lookup(n); p.Sensitivity == "S3" && !raw {
			return m, ErrRawGrant
		}
	}
	m.Filters["scope"] = scope
	if !from.IsZero() {
		m.Filters["from"] = from.UTC()
	}
	if !to.IsZero() {
		m.Filters["to"] = to.UTC()
	}
	m.Filters["parameters"] = names

	dir := filepath.Join(x.Dir, m.DatasetID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return m, err
	}
	key, err := x.newKey(m.DatasetID)
	if err != nil {
		return m, err
	}
	if req.Format == GraphML && req.Subgraph == SubgraphAudit {
		if err := x.exportAuditGraphML(&m, dir, key, scope, from, to); err != nil {
			os.RemoveAll(dir)
			return m, err
		}
	} else if req.Format == GraphML {
		if err := x.exportGraphML(&m, dir, key, req.SnapshotID); err != nil {
			os.RemoveAll(dir)
			return m, err
		}
	} else if err := x.exportRecords(&m, dir, key, names, scope, from, to, req.Format); err != nil {
		os.RemoveAll(dir)
		return m, err
	}
	if m.Campaign != nil && x.Campaigns != nil {
		if err := x.Campaigns.MarkExported(m.Campaign.ID, m.DatasetID, actor); err != nil {
			return m, err
		}
	}
	return m, nil
}

// scopeFilter is the store filter of an extraction scope and time range.
func scopeFilter(scope Scope, from, to time.Time) obsstore.Filter {
	f := obsstore.Filter{From: from, To: to, Equals: map[string][]string{}}
	if len(scope.Principals) > 0 {
		f.Equals["principal_id"] = scope.Principals
	}
	if len(scope.Servers) > 0 {
		f.Equals["server_id"] = scope.Servers
	}
	if len(scope.Tools) > 0 {
		f.Equals["tool_name"] = scope.Tools
	}
	return f
}

func (x *Exporter) exportRecords(m *Manifest, dir string, key []byte, names []string, scope Scope, from, to time.Time, format string) error {
	// Columns: time, pseudonymized call ID, identifiers, the selection.
	cols := []obsstore.Column{{Name: "ts", Type: obsstore.Timestamp}, {Name: "correlation_id", Type: obsstore.Varchar}}
	seen := map[string]bool{"ts": true, "correlation_id": true}
	add := func(n string) {
		if seen[n] {
			return
		}
		seen[n] = true
		p, _ := x.Catalog.Lookup(n)
		t := columnType(p)
		if pseudonymized[n] || p.Sensitivity == "S2" {
			t = obsstore.Varchar
		}
		cols = append(cols, obsstore.Column{Name: n, Type: t})
	}
	for _, n := range observe.Identifiers {
		add(n)
	}
	for _, n := range names {
		add(n)
	}
	cols = append(cols, obsstore.Column{Name: "capture", Type: obsstore.Varchar})
	for _, c := range cols {
		m.Columns = append(m.Columns, c.Name)
	}
	f := scopeFilter(scope, from, to)
	jsonlPath := filepath.Join(dir, "dataset.jsonl")
	jf, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	jw := bufio.NewWriter(jf)
	enc := json.NewEncoder(jw)
	var cw *csv.Writer
	var cf *os.File
	if format == CSV {
		if cf, err = os.OpenFile(filepath.Join(dir, "dataset.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err != nil {
			jf.Close()
			return err
		}
		cw = csv.NewWriter(cf)
		if err := cw.Write(m.Columns); err != nil {
			jf.Close()
			cf.Close()
			return err
		}
	}
	revs, snaps := map[string]bool{}, map[string]bool{}
	var first, last time.Time
	err = x.Store.Scan("records", f, func(r obsstore.Row) error {
		if s, _ := r["policy_revision"].(string); s != "" {
			revs[s] = true
		}
		if s, _ := r["baseline_snapshot_id"].(string); s != "" {
			snaps[s] = true
		}
		ts := r["ts"].(time.Time)
		if first.IsZero() || ts.Before(first) {
			first = ts
		}
		if ts.After(last) {
			last = ts
		}
		obj := map[string]any{}
		for _, c := range cols {
			v, ok := r[c.Name]
			if !ok || v == nil {
				continue
			}
			p, _ := x.Catalog.Lookup(c.Name)
			if pseudonymized[c.Name] || p.Sensitivity == "S2" {
				v = pseudonymize(key, v)
			}
			if t, ok := v.(time.Time); ok {
				v = t.UTC().Format("2006-01-02 15:04:05.000000")
			}
			obj[c.Name] = v
		}
		m.Rows++
		if err := enc.Encode(obj); err != nil {
			return err
		}
		if cw != nil {
			rec := make([]string, len(cols))
			for i, c := range cols {
				rec[i] = csvCell(obj[c.Name])
			}
			return cw.Write(rec)
		}
		return nil
	})
	if ferr := jw.Flush(); err == nil {
		err = ferr
	}
	if cerr := jf.Close(); err == nil {
		err = cerr
	}
	if cw != nil {
		cw.Flush()
		if err == nil {
			err = cw.Error()
		}
		if cerr := cf.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return err
	}
	m.PolicyRevisions = sortedKeys(revs)
	m.BaselineSnapshots = sortedKeys(snaps)
	if !first.IsZero() {
		m.TimeRange = map[string]any{"first": first, "last": last}
	}
	data := "dataset.jsonl"
	switch format {
	case CSV:
		os.Remove(jsonlPath)
		data = "dataset.csv"
	case Parquet:
		pw := x.Store.(obsstore.ParquetWriter)
		if err := pw.WriteParquet(cols, jsonlPath, filepath.Join(dir, "dataset.parquet")); err != nil {
			return err
		}
		os.Remove(jsonlPath)
		data = "dataset.parquet"
	}
	dict := x.dictionary(cols)
	return finish(m, dir, data, dict)
}

// csvCell renders a value; a string starting with =, +, - or @ is prefixed
// with an apostrophe so that spreadsheets treat it as text (SR-6.17-1).
func csvCell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		if x != "" && strings.ContainsRune("=+-@\t\r", rune(x[0])) {
			return "'" + x
		}
		return x
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case int64:
		return strconv.FormatInt(x, 10)
	case bool:
		return strconv.FormatBool(x)
	default:
		b, _ := json.Marshal(x)
		s := string(b)
		if s != "" && strings.ContainsRune("=+-@", rune(s[0])) {
			return "'" + s
		}
		return s
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DictEntry is one data dictionary entry, generated from the catalog.
type DictEntry struct {
	Column        string `json:"column"`
	Type          string `json:"type"`
	ID            string `json:"id,omitempty"`
	Description   string `json:"description"`
	Unit          string `json:"unit,omitempty"`
	DataType      string `json:"data_type,omitempty"`
	Derivation    string `json:"derivation,omitempty"`
	Sensitivity   string `json:"sensitivity,omitempty"`
	SourceElement string `json:"source_element,omitempty"`
	Pseudonymized bool   `json:"pseudonymized"`
}

var metaDescriptions = map[string]string{
	"ts":             "Time of the call's requested event (UTC)",
	"correlation_id": "Call correlation ID",
	"capture":        "Why the record was stored: sampled, escalated or campaign",
}

func (x *Exporter) dictionary(cols []obsstore.Column) []DictEntry {
	var out []DictEntry
	for _, c := range cols {
		e := DictEntry{Column: c.Name, Type: c.Type, Pseudonymized: pseudonymized[c.Name]}
		if p, ok := x.Catalog.Lookup(c.Name); ok {
			e.ID, e.Description, e.Unit, e.DataType, e.Derivation, e.Sensitivity, e.SourceElement =
				p.ID, p.Description, p.Unit, p.DataType, p.Derivation, p.Sensitivity, p.SourceElement
			e.Pseudonymized = e.Pseudonymized || p.Sensitivity == "S2"
		} else {
			e.Description = metaDescriptions[c.Name]
		}
		out = append(out, e)
	}
	return out
}

// finish writes the dictionary, the manifest and the checksum file.
func finish(m *Manifest, dir, data string, dict any) error {
	db, err := json.MarshalIndent(dict, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "dictionary.json"), db, 0o600); err != nil {
		return err
	}
	for _, n := range []string{data, "dictionary.json"} {
		f, err := fileInfo(filepath.Join(dir, n))
		if err != nil {
			return err
		}
		m.Files = append(m.Files, f)
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), mb, 0o600); err != nil {
		return err
	}
	mf, err := fileInfo(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return err
	}
	var sb strings.Builder
	for _, f := range append(slices.Clone(m.Files), mf) {
		fmt.Fprintf(&sb, "%s  %s\n", f.SHA256, f.Name)
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sb.String()), 0o600)
}

func fileInfo(path string) (File, error) {
	f, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return File{}, err
	}
	return File{Name: filepath.Base(path), Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// graphml document types.
type gmlKey struct {
	ID   string `xml:"id,attr"`
	For  string `xml:"for,attr"`
	Name string `xml:"attr.name,attr"`
	Type string `xml:"attr.type,attr"`
}
type gmlData struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}
type gmlNode struct {
	ID   string    `xml:"id,attr"`
	Data []gmlData `xml:"data"`
}
type gmlEdge struct {
	Source string    `xml:"source,attr"`
	Target string    `xml:"target,attr"`
	Data   []gmlData `xml:"data"`
}
type gmlGraph struct {
	ID          string    `xml:"id,attr"`
	EdgeDefault string    `xml:"edgedefault,attr"`
	Nodes       []gmlNode `xml:"node"`
	Edges       []gmlEdge `xml:"edge"`
}
type gmlDoc struct {
	XMLName xml.Name `xml:"graphml"`
	XMLNS   string   `xml:"xmlns,attr"`
	Keys    []gmlKey `xml:"key"`
	Graph   gmlGraph `xml:"graph"`
}

// exportGraphML writes the behavior model of a snapshot: one node per
// baseline context and per tool, a COVERS edge from each context to its
// tool, and NEXT_TOOL edges with transition counts (ArchitectureV2 §13.1).
// Principal and end-user values are pseudonymized.
func (x *Exporter) exportGraphML(m *Manifest, dir string, key []byte, id string) error {
	if x.Snapshots == nil {
		return ErrNoSnapshot
	}
	if id == "" {
		id, _ = x.Snapshots.Promoted()
	}
	if id == "" {
		return ErrNoSnapshot
	}
	snap, err := x.Snapshots.Load(id)
	if err != nil {
		return err
	}
	m.BaselineSnapshots = []string{snap.ID}
	m.TimeRange = map[string]any{"first": snap.Window.From, "last": snap.Window.To}
	doc := gmlDoc{XMLNS: "http://graphml.graphdrawing.org/xmlns", Keys: []gmlKey{
		{"label", "node", "label", "string"}, {"kind", "node", "kind", "string"}, {"count", "node", "count", "long"},
		{"stats", "node", "stats", "string"}, {"rel", "edge", "type", "string"}, {"weight", "edge", "count", "long"},
		{"seq", "edge", "sequence_context", "string"},
	}, Graph: gmlGraph{ID: "behavior-model-" + snap.ID, EdgeDefault: "directed"}}
	pseudoDims := func(d map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range d {
			if k == "principal" || k == "end_user" {
				v = Pseudonym(key, v)
			}
			out[k] = v
		}
		return out
	}
	toolNode := map[string]bool{}
	addTool := func(t string) string {
		id := "tool:" + t
		if !toolNode[t] {
			toolNode[t] = true
			doc.Graph.Nodes = append(doc.Graph.Nodes, gmlNode{ID: id, Data: []gmlData{{"label", t}, {"kind", "Tool"}}})
		}
		return id
	}
	keys := make([]string, 0, len(snap.Contexts))
	for k := range snap.Contexts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		cs := snap.Contexts[k]
		dims := pseudoDims(cs.Dims)
		label := baseline.ContextKey(snap.Config.Dimensions, dims)
		stats, _ := json.Marshal(cs.Features)
		nid := "ctx:" + strconv.Itoa(i)
		doc.Graph.Nodes = append(doc.Graph.Nodes, gmlNode{ID: nid, Data: []gmlData{{"label", label}, {"kind", "BaselineContext"},
			{"count", strconv.FormatInt(cs.Count, 10)}, {"stats", string(stats)}}})
		if t := cs.Dims["tool"]; t != "" {
			doc.Graph.Edges = append(doc.Graph.Edges, gmlEdge{Source: nid, Target: addTool(t), Data: []gmlData{{"rel", "COVERS"}}})
		}
	}
	seqKeys := make([]string, 0, len(snap.Transitions))
	for k := range snap.Transitions {
		seqKeys = append(seqKeys, k)
	}
	sort.Strings(seqKeys)
	for _, sk := range seqKeys {
		label := pseudoSeqKey(key, sk)
		prevs := sortedKeys(boolKeys(snap.Transitions[sk]))
		for _, prev := range prevs {
			nexts := snap.Transitions[sk][prev]
			nk := make([]string, 0, len(nexts))
			for n := range nexts {
				nk = append(nk, n)
			}
			sort.Strings(nk)
			for _, next := range nk {
				doc.Graph.Edges = append(doc.Graph.Edges, gmlEdge{Source: addTool(prev), Target: addTool(next),
					Data: []gmlData{{"rel", "NEXT_TOOL"}, {"weight", strconv.FormatInt(nexts[next], 10)}, {"seq", label}}})
			}
		}
	}
	m.Rows = int64(len(doc.Graph.Nodes))
	m.Columns = []string{"nodes:BaselineContext,Tool", "edges:COVERS,NEXT_TOOL"}
	out, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "behavior-model.graphml"), append([]byte(xml.Header), out...), 0o600); err != nil {
		return err
	}
	dict := []DictEntry{
		{Column: "node kind BaselineContext", Description: "Baseline context: label is the context key (principal and end-user pseudonymized), count the sample count, stats the per-feature statistics", Pseudonymized: true},
		{Column: "node kind Tool", Description: "Backend tool name"},
		{Column: "edge COVERS", Description: "Context to the tool it covers"},
		{Column: "edge NEXT_TOOL", Description: "Tool transition with its count in the sequence context"},
	}
	return finish(m, dir, "behavior-model.graphml", dict)
}

// exportAuditGraphML writes the audit subgraph of the records in scope:
// one Call node per record (pseudonymized correlation ID, time, decision
// outcome), Session and Principal nodes (pseudonymized), Tool nodes
// (server and tool) and PolicyRevision nodes, with OPENED (principal to
// session), MADE (session to call), INVOKED (call to tool) and
// DECIDED_UNDER (call to policy revision) edges, after the Appendix D
// audit relationships. The number of Call nodes equals the rows of a
// tabular export of the same scope.
func (x *Exporter) exportAuditGraphML(m *Manifest, dir string, key []byte, scope Scope, from, to time.Time) error {
	doc := gmlDoc{XMLNS: "http://graphml.graphdrawing.org/xmlns", Keys: []gmlKey{
		{"label", "node", "label", "string"}, {"kind", "node", "kind", "string"}, {"ts", "node", "ts", "string"},
		{"outcome", "node", "decision_outcome", "string"}, {"rel", "edge", "type", "string"},
	}, Graph: gmlGraph{ID: "audit-" + m.DatasetID, EdgeDefault: "directed"}}
	nodes := map[string]bool{}
	node := func(id, kind, label string, extra ...gmlData) string {
		if !nodes[id] {
			nodes[id] = true
			doc.Graph.Nodes = append(doc.Graph.Nodes, gmlNode{ID: id, Data: append([]gmlData{{"label", label}, {"kind", kind}}, extra...)})
		}
		return id
	}
	edges := map[string]bool{}
	edge := func(src, dst, rel string) {
		if k := src + "\x00" + dst + "\x00" + rel; !edges[k] {
			edges[k] = true
			doc.Graph.Edges = append(doc.Graph.Edges, gmlEdge{Source: src, Target: dst, Data: []gmlData{{"rel", rel}}})
		}
	}
	str := func(r obsstore.Row, k string) string { s, _ := r[k].(string); return s }
	revs := map[string]bool{}
	var first, last time.Time
	err := x.Store.Scan("records", scopeFilter(scope, from, to), func(r obsstore.Row) error {
		ts, _ := r["ts"].(time.Time)
		if first.IsZero() || ts.Before(first) {
			first = ts
		}
		if ts.After(last) {
			last = ts
		}
		call := Pseudonym(key, str(r, "correlation_id"))
		cid := node("call:"+call, "Call", call, gmlData{"ts", ts.UTC().Format(time.RFC3339Nano)}, gmlData{"outcome", str(r, "decision_outcome")})
		m.Rows++
		if s := str(r, "session_id"); s != "" {
			ps := Pseudonym(key, s)
			sid := node("session:"+ps, "Session", ps)
			edge(sid, cid, "MADE")
			if p := str(r, "principal_id"); p != "" {
				pp := Pseudonym(key, p)
				edge(node("principal:"+pp, "Principal", pp), sid, "OPENED")
			}
		}
		if t := str(r, "tool_name"); t != "" {
			label := str(r, "server_id") + "/" + t
			edge(cid, node("tool:"+label, "Tool", label), "INVOKED")
		}
		if rev := str(r, "policy_revision"); rev != "" {
			revs[rev] = true
			edge(cid, node("policy:"+rev, "PolicyRevision", rev), "DECIDED_UNDER")
		}
		return nil
	})
	if err != nil {
		return err
	}
	m.PolicyRevisions = sortedKeys(revs)
	if !first.IsZero() {
		m.TimeRange = map[string]any{"first": first, "last": last}
	}
	m.Columns = []string{"nodes:Call,Session,Principal,Tool,PolicyRevision", "edges:OPENED,MADE,INVOKED,DECIDED_UNDER"}
	out, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "audit.graphml"), append([]byte(xml.Header), out...), 0o600); err != nil {
		return err
	}
	dict := []DictEntry{
		{Column: "node kind Call", Description: "One observed tool call: label is the pseudonymized correlation ID, ts its time, decision_outcome the policy outcome", Pseudonymized: true},
		{Column: "node kind Session", Description: "Gateway session (pseudonymized session ID)", Pseudonymized: true},
		{Column: "node kind Principal", Description: "Framework instance (pseudonymized principal ID)", Pseudonymized: true},
		{Column: "node kind Tool", Description: "Server alias and tool name"},
		{Column: "node kind PolicyRevision", Description: "Policy revision the call was decided under"},
		{Column: "edges", Description: "OPENED principal to session, MADE session to call, INVOKED call to tool, DECIDED_UNDER call to policy revision"},
	}
	return finish(m, dir, "audit.graphml", dict)
}

func boolKeys[V any](m map[string]V) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// pseudoSeqKey pseudonymizes the principal and end_user values of a
// sequence-context key.
func pseudoSeqKey(key []byte, sk string) string {
	if sk == "*" {
		return sk
	}
	parts := strings.Split(sk, "|")
	for i, p := range parts {
		if k, v, ok := strings.Cut(p, "="); ok && (k == "principal" || k == "end_user") {
			parts[i] = k + "=" + Pseudonym(key, v)
		}
	}
	return strings.Join(parts, "|")
}

// List returns the manifests of the exports in the directory, newest first.
func (x *Exporter) List() ([]Manifest, error) {
	ents, err := os.ReadDir(x.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return []Manifest{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Manifest{}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		m, err := x.Manifest(e.Name())
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DatasetID > out[j].DatasetID })
	return out, nil
}

// Manifest reads one export's manifest.
func (x *Exporter) Manifest(id string) (Manifest, error) {
	var m Manifest
	if !safeName.MatchString(id) {
		return m, os.ErrNotExist
	}
	raw, err := os.ReadFile(filepath.Join(x.Dir, id, "manifest.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(raw, &m)
}

// Open opens one file of an export for download.
func (x *Exporter) Open(id, name string) (*os.File, error) {
	if !safeName.MatchString(id) || !safeName.MatchString(name) {
		return nil, os.ErrNotExist
	}
	// OpenInRoot also refuses a symbolic link that leads out of the
	// export directory.
	return os.OpenInRoot(x.Dir, filepath.Join(id, name))
}

// Retain deletes every exported dataset created before now-keep, with its
// pseudonymization key, and returns the removed dataset IDs (FR-9.14:
// research data follows the Observation Policy's retention). keep <= 0
// keeps everything. A directory without a readable manifest is left alone.
func (x *Exporter) Retain(now time.Time, keep time.Duration) ([]string, error) {
	if keep <= 0 || x.Dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(x.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-keep)
	var removed []string
	var errs []error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := x.Manifest(e.Name())
		if err != nil || m.CreatedAt.IsZero() || !m.CreatedAt.Before(cutoff) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(x.Dir, e.Name())); err != nil {
			errs = append(errs, err)
			continue
		}
		if x.KeyDir != "" {
			if err := os.Remove(filepath.Join(x.KeyDir, e.Name()+".key")); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		removed = append(removed, e.Name())
	}
	return removed, errors.Join(errs...)
}
