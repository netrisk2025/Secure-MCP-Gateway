package secrets

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/ethan03805/secure-mcp-gateway/internal/config"
)

// Delivery modes (ARCH §8.2), in preference order.
const (
	ModeS1 = "S1" // header injection by the Egress Broker
	ModeS2 = "S2" // per-call file
	ModeS3 = "S3" // per-instance file
	ModeS4 = "S4" // launch environment variable, waiver only
)

//go:embed usepolicy.schema.json
var usePolicySchemaJSON []byte

// UsePolicySchemaJSON returns the published Secret Use Policy schema.
func UsePolicySchemaJSON() []byte { return slices.Clone(usePolicySchemaJSON) }

var usePolicySchema = func() *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(usePolicySchemaJSON))
	if err != nil {
		panic("embedded use policy schema: " + err.Error())
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("usepolicy.schema.json", doc); err != nil {
		panic(err)
	}
	s, err := c.Compile("usepolicy.schema.json")
	if err != nil {
		panic("compile use policy schema: " + err.Error())
	}
	return s
}()

// UsePolicyDoc is the Secret Use Policy file as written.
type UsePolicyDoc struct {
	Revision string      `json:"revision"`
	Slots    []Slot      `json:"slots,omitempty"`
	Policies []UsePolicy `json:"policies,omitempty"`
}

// Slot is a server's declared secret slot: the delivery modes it supports
// and how each is presented. Until signed manifests (E-13) declare slots,
// the Secret Use Policy file declares them, and each `secret_env` entry of
// a server's configuration declares an S4-only slot named after the
// variable.
type Slot struct {
	Server         string   `json:"server"`
	Name           string   `json:"name"`
	Modes          []string `json:"modes"`
	Env            string   `json:"env,omitempty"`
	FileEnv        string   `json:"file_env,omitempty"`
	Header         string   `json:"header,omitempty"`
	HeaderTemplate string   `json:"header_template,omitempty"`
	Destination    string   `json:"destination,omitempty"`
}

// Hours is a daily window in the Gateway's local time; End before Start
// spans midnight.
type Hours struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// Waiver is the approved exception that permits mode S4 (FR-6.9).
type Waiver struct {
	ApprovedBy string `json:"approved_by"`
	Reason     string `json:"reason"`
	Expires    string `json:"expires,omitempty"`
}

// UsePolicy binds one secret to one server slot (FR-6.5).
type UsePolicy struct {
	ID             string   `json:"id"`
	Secret         string   `json:"secret"`
	Version        int      `json:"version,omitempty"`
	Server         string   `json:"server"`
	Slot           string   `json:"slot"`
	Mode           string   `json:"mode"`
	Tools          []string `json:"tools"`
	Destination    string   `json:"destination,omitempty"`
	Purpose        string   `json:"purpose"`
	SessionPurpose string   `json:"session_purpose,omitempty"`
	CallsPerMinute int      `json:"calls_per_minute,omitempty"`
	NotBefore      string   `json:"not_before,omitempty"`
	NotAfter       string   `json:"not_after,omitempty"`
	Hours          *Hours   `json:"hours,omitempty"`
	Approval       bool     `json:"approval,omitempty"`
	Waiver         *Waiver  `json:"s4_waiver,omitempty"`
}

// binding is a compiled UsePolicy with its slot.
type binding struct {
	UsePolicy
	slot        Slot
	notBefore   time.Time
	notAfter    time.Time
	waiverUntil time.Time
	startMin    int
	endMin      int
}

// UseSet is a compiled Secret Use Policy.
type UseSet struct {
	Revision string
	Digest   string
	bindings []*binding
	byServer map[string][]*binding
	slots    map[string]Slot // server/slot
}

func slotKey(server, slot string) string { return server + "/" + slot }

// LoadUsePolicy reads and compiles a Secret Use Policy file. An empty path
// yields an empty policy: no secret is bound to any server.
func LoadUsePolicy(path string, servers []config.Server) (*UseSet, error) {
	if path == "" {
		return CompileUsePolicy([]byte(`{"revision":"none"}`), servers)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	u, err := CompileUsePolicy(raw, servers)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return u, nil
}

// CompileUsePolicy validates a Secret Use Policy against the schema and the
// declared slots and compiles it. It rejects a binding whose slot is not
// declared, whose mode the slot does not support (ARCH §8.2), S4 without a
// waiver or where the slot supports another mode (FR-6.9), S1 without a
// header and destination, S2 and S3 without a file variable, launch-time
// modes restricted to some tools or requiring approval, and two bindings
// of one slot.
func CompileUsePolicy(raw []byte, servers []config.Server) (*UseSet, error) {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := usePolicySchema.Validate(inst); err != nil {
		return nil, fmt.Errorf("secret use policy does not match schema: %w", err)
	}
	var doc UsePolicyDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	sum := sha256.Sum256(raw)
	u := &UseSet{Revision: doc.Revision, Digest: hex.EncodeToString(sum[:]), byServer: map[string][]*binding{}, slots: map[string]Slot{}}
	known := map[string]config.Server{}
	for _, s := range servers {
		known[s.Alias] = s
	}
	for _, s := range doc.Slots {
		if _, ok := known[s.Server]; !ok {
			return nil, fmt.Errorf("slot %s: unknown server %q", s.Name, s.Server)
		}
		k := slotKey(s.Server, s.Name)
		if _, dup := u.slots[k]; dup {
			return nil, fmt.Errorf("slot %s declared twice", k)
		}
		if slices.Contains(s.Modes, ModeS1) && (s.Header == "" || s.Destination == "") {
			return nil, fmt.Errorf("slot %s: S1 needs header and destination", k)
		}
		if s.HeaderTemplate != "" && !strings.Contains(s.HeaderTemplate, "{secret}") {
			return nil, fmt.Errorf("slot %s: header_template must contain {secret}", k)
		}
		if (slices.Contains(s.Modes, ModeS2) || slices.Contains(s.Modes, ModeS3)) && s.FileEnv == "" {
			return nil, fmt.Errorf("slot %s: S2 and S3 need file_env", k)
		}
		if slices.Contains(s.Modes, ModeS4) && s.Env == "" {
			return nil, fmt.Errorf("slot %s: S4 needs env", k)
		}
		u.slots[k] = s
	}
	// Each secret_env entry declares an S4-only slot named after the
	// variable, unless the policy file declares that slot itself.
	for _, s := range servers {
		for env := range s.SecretEnv {
			k := slotKey(s.Alias, env)
			if _, ok := u.slots[k]; !ok {
				u.slots[k] = Slot{Server: s.Alias, Name: env, Modes: []string{ModeS4}, Env: env}
			}
		}
	}
	ids := map[string]bool{}
	for _, p := range doc.Policies {
		b, err := compileBinding(p, u.slots, known)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", p.ID, err)
		}
		if ids[p.ID] {
			return nil, fmt.Errorf("policy id %q used twice", p.ID)
		}
		ids[p.ID] = true
		for _, o := range u.byServer[p.Server] {
			if o.Slot == p.Slot {
				return nil, fmt.Errorf("policy %s: slot %s is already bound by policy %s", p.ID, slotKey(p.Server, p.Slot), o.ID)
			}
		}
		u.bindings = append(u.bindings, b)
		u.byServer[p.Server] = append(u.byServer[p.Server], b)
	}
	return u, nil
}

func parseClock(s string) int {
	var h, m int
	_, _ = fmt.Sscanf(s, "%d:%d", &h, &m)
	return h*60 + m
}

func compileBinding(p UsePolicy, slots map[string]Slot, servers map[string]config.Server) (*binding, error) {
	srv, ok := servers[p.Server]
	if !ok {
		return nil, fmt.Errorf("unknown server %q", p.Server)
	}
	slot, ok := slots[slotKey(p.Server, p.Slot)]
	if !ok {
		return nil, fmt.Errorf("server %s declares no slot %q", p.Server, p.Slot)
	}
	if !slices.Contains(slot.Modes, p.Mode) {
		return nil, fmt.Errorf("slot %s supports %v, not %s", p.Slot, slot.Modes, p.Mode)
	}
	if ref, ok := srv.SecretEnv[p.Slot]; ok && ref != p.Secret {
		return nil, fmt.Errorf("server %s secret_env names secret %q for %s, the policy names %q", p.Server, ref, p.Slot, p.Secret)
	}
	b := &binding{UsePolicy: p, slot: slot}
	var err error
	if p.NotBefore != "" {
		if b.notBefore, err = time.Parse(time.RFC3339, p.NotBefore); err != nil {
			return nil, err
		}
	}
	if p.NotAfter != "" {
		if b.notAfter, err = time.Parse(time.RFC3339, p.NotAfter); err != nil {
			return nil, err
		}
	}
	if p.Hours != nil {
		b.startMin, b.endMin = parseClock(p.Hours.Start), parseClock(p.Hours.End)
		if b.startMin == b.endMin {
			return nil, errors.New("hours start and end are equal")
		}
	}
	launchTime := p.Mode == ModeS3 || p.Mode == ModeS4 || p.Mode == ModeS1
	if launchTime && !slices.Equal(p.Tools, []string{"*"}) {
		return nil, fmt.Errorf("mode %s is bound for the instance lifetime, so tools must be [\"*\"]", p.Mode)
	}
	if launchTime && (p.Approval || p.SessionPurpose != "" || p.CallsPerMinute > 0) {
		return nil, fmt.Errorf("mode %s is delivered at launch; approval, session_purpose and calls_per_minute apply to S2 only", p.Mode)
	}
	switch p.Mode {
	case ModeS1:
		if p.Destination != "" && p.Destination != slot.Destination {
			return nil, fmt.Errorf("destination %q differs from the slot's %q", p.Destination, slot.Destination)
		}
		b.Destination = slot.Destination
	case ModeS4:
		if p.Waiver == nil {
			return nil, errors.New("mode S4 needs an approved s4_waiver (FR-6.9)")
		}
		if len(slot.Modes) != 1 {
			return nil, fmt.Errorf("mode S4 is refused because slot %s supports %v (FR-6.9)", p.Slot, slot.Modes)
		}
		if p.Waiver.Expires != "" {
			if b.waiverUntil, err = time.Parse(time.RFC3339, p.Waiver.Expires); err != nil {
				return nil, err
			}
		}
	}
	if p.Mode != ModeS4 && p.Waiver != nil {
		return nil, errors.New("s4_waiver is only valid with mode S4")
	}
	return b, nil
}

// inWindow reports whether t is inside the binding's time window.
func (b *binding) inWindow(t time.Time) bool {
	if !b.notBefore.IsZero() && t.Before(b.notBefore) {
		return false
	}
	if !b.notAfter.IsZero() && !t.Before(b.notAfter) {
		return false
	}
	if b.Mode == ModeS4 && !b.waiverUntil.IsZero() && !t.Before(b.waiverUntil) {
		return false
	}
	if b.Hours != nil {
		lt := t.Local()
		m := lt.Hour()*60 + lt.Minute()
		if b.startMin < b.endMin {
			return m >= b.startMin && m < b.endMin
		}
		return m >= b.startMin || m < b.endMin
	}
	return true
}

func (b *binding) permitsTool(tool string) bool {
	return slices.Contains(b.Tools, "*") || slices.Contains(b.Tools, tool)
}

// Binding is the report form of one compiled binding.
type Binding struct {
	UsePolicy
	SlotModes []string `json:"slot_modes"`
}

// BindingsFor returns the bindings of the given servers (FR-6.5, the
// effective permission report).
func (u *UseSet) BindingsFor(servers []string) any {
	out := []Binding{}
	for _, b := range u.Bindings() {
		if slices.Contains(servers, b.Server) {
			out = append(out, b)
		}
	}
	return out
}

// Bindings returns every binding, ordered by server and slot.
func (u *UseSet) Bindings() []Binding {
	out := make([]Binding, 0, len(u.bindings))
	for _, b := range u.bindings {
		out = append(out, Binding{UsePolicy: b.UsePolicy, SlotModes: b.slot.Modes})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return out[i].Server < out[j].Server
		}
		return out[i].Slot < out[j].Slot
	})
	return out
}

// Slots returns every declared slot, including the S4-only slots of
// secret_env entries.
func (u *UseSet) Slots() []Slot {
	out := make([]Slot, 0, len(u.slots))
	for _, s := range u.slots {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return slotKey(out[i].Server, out[i].Name) < slotKey(out[j].Server, out[j].Name) })
	return out
}
