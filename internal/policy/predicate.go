package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Predicate operators (SR-1.7-1). No other operator is accepted: the
// schema and Compile refuse an unknown one.
const (
	OpEq          = "eq"            // exact equality with a scalar
	OpIn          = "in"            // set membership
	OpRange       = "range"         // inclusive numeric range
	OpPathWithin  = "path_within"   // canonical path containment
	OpURLIn       = "url_in"        // scheme, host and port membership
	OpDataClassIn = "data_class_in" // data-class membership
	OpExpiry      = "expiry"        // UTC validity interval of the rule
	OpApproval    = "approval"      // approval state: "required"
)

// Operators lists the predicate operators in documentation order.
var Operators = []string{OpEq, OpIn, OpRange, OpPathWithin, OpURLIn, OpDataClassIn, OpExpiry, OpApproval}

// Predicate is one argument constraint of a permit rule (FR-3.6). A permit
// rule applies only when every predicate holds; a predicate that names a
// missing or malformed argument does not hold, so the rule does not permit
// the call (SR-1.7-2).
type Predicate struct {
	Op string `json:"op"`
	// Arg names the argument: a top-level member, or members separated by
	// "." for nested objects. Not used by expiry and approval.
	Arg   string          `json:"arg,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
	Min   *float64        `json:"min,omitempty"`
	Max   *float64        `json:"max,omitempty"`
	// NotBefore and NotAfter bound expiry (RFC 3339, UTC).
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`

	values    []any // eq (one), in, data_class_in
	roots     []string
	origins   []origin
	notBefore time.Time
	notAfter  time.Time
}

type origin struct {
	scheme, host string
	port         int
}

func defaultPortOf(scheme string) int {
	switch scheme {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

// compile validates a predicate and prepares it for evaluation.
func (p *Predicate) compile() error {
	needArg := p.Op != OpExpiry && p.Op != OpApproval
	if needArg && strings.TrimSpace(p.Arg) == "" {
		return fmt.Errorf("predicate %q needs arg", p.Op)
	}
	switch p.Op {
	case OpEq:
		var v any
		if err := json.Unmarshal(p.Value, &v); err != nil {
			return fmt.Errorf("eq: value: %w", err)
		}
		switch v.(type) {
		case string, float64, bool:
		default:
			return fmt.Errorf("eq: value must be a string, number or boolean")
		}
		p.values = []any{v}
	case OpIn, OpDataClassIn:
		var vs []any
		if err := json.Unmarshal(p.Value, &vs); err != nil || len(vs) == 0 {
			return fmt.Errorf("%s: value must be a non-empty list", p.Op)
		}
		for _, v := range vs {
			switch v.(type) {
			case string, float64, bool:
			default:
				return fmt.Errorf("%s: list members must be strings, numbers or booleans", p.Op)
			}
		}
		p.values = vs
	case OpRange:
		if p.Min == nil && p.Max == nil {
			return fmt.Errorf("range needs min, max or both")
		}
		if p.Min != nil && p.Max != nil && *p.Min > *p.Max {
			return fmt.Errorf("range: min is above max")
		}
	case OpPathWithin:
		var roots []string
		if err := json.Unmarshal(p.Value, &roots); err != nil || len(roots) == 0 {
			return fmt.Errorf("path_within: value must be a non-empty list of absolute paths")
		}
		for _, r := range roots {
			if !path.IsAbs(r) || strings.ContainsRune(r, 0) {
				return fmt.Errorf("path_within: %q is not an absolute path", r)
			}
			p.roots = append(p.roots, path.Clean(r))
		}
	case OpURLIn:
		var us []string
		if err := json.Unmarshal(p.Value, &us); err != nil || len(us) == 0 {
			return fmt.Errorf("url_in: value must be a non-empty list of scheme://host[:port]")
		}
		for _, s := range us {
			o, err := parseOrigin(s)
			if err != nil {
				return fmt.Errorf("url_in: %q: %w", s, err)
			}
			p.origins = append(p.origins, o)
		}
	case OpExpiry:
		if p.NotBefore == "" && p.NotAfter == "" {
			return fmt.Errorf("expiry needs not_before, not_after or both")
		}
		var err error
		if p.NotBefore != "" {
			if p.notBefore, err = time.Parse(time.RFC3339, p.NotBefore); err != nil {
				return fmt.Errorf("expiry: not_before: %w", err)
			}
		}
		if p.NotAfter != "" {
			if p.notAfter, err = time.Parse(time.RFC3339, p.NotAfter); err != nil {
				return fmt.Errorf("expiry: not_after: %w", err)
			}
		}
		if !p.notBefore.IsZero() && !p.notAfter.IsZero() && !p.notBefore.Before(p.notAfter) {
			return fmt.Errorf("expiry: not_before is not before not_after")
		}
	case OpApproval:
		var v string
		if err := json.Unmarshal(p.Value, &v); err != nil || v != "required" {
			return fmt.Errorf(`approval: value must be "required"`)
		}
	default:
		return fmt.Errorf("unknown predicate operator %q (SR-1.7-1)", p.Op)
	}
	return nil
}

func parseOrigin(s string) (origin, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" {
		return origin{}, fmt.Errorf("not scheme://host[:port]")
	}
	o := origin{scheme: strings.ToLower(u.Scheme), host: strings.ToLower(u.Hostname())}
	if ps := u.Port(); ps != "" {
		if o.port, err = strconv.Atoi(ps); err != nil || o.port < 1 || o.port > 65535 {
			return origin{}, fmt.Errorf("bad port")
		}
	} else {
		o.port = defaultPortOf(o.scheme)
	}
	return o, nil
}

// lookup returns the argument a dotted name points at.
func lookup(args map[string]any, name string) (any, bool) {
	var cur any = args
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func scalarEqual(a, b any) bool {
	switch x := a.(type) {
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	}
	return false
}

// holds evaluates the predicate. args is nil when the arguments are not a
// JSON object; a predicate on an argument then does not hold.
func (p *Predicate) holds(args map[string]any, now time.Time) bool {
	switch p.Op {
	case OpExpiry:
		return (p.notBefore.IsZero() || !now.Before(p.notBefore)) && (p.notAfter.IsZero() || now.Before(p.notAfter))
	case OpApproval:
		return true // an obligation, applied by the caller
	}
	v, ok := lookup(args, p.Arg)
	if !ok {
		return false
	}
	switch p.Op {
	case OpEq:
		return scalarEqual(v, p.values[0])
	case OpIn, OpDataClassIn:
		return slices.ContainsFunc(p.values, func(x any) bool { return scalarEqual(v, x) })
	case OpRange:
		f, ok := v.(float64)
		if !ok || math.IsNaN(f) {
			return false
		}
		return (p.Min == nil || f >= *p.Min) && (p.Max == nil || f <= *p.Max)
	case OpPathWithin:
		s, ok := v.(string)
		if !ok || !path.IsAbs(s) || strings.ContainsRune(s, 0) || strings.Contains(s, "\\") {
			return false
		}
		c := path.Clean(s)
		for _, r := range p.roots {
			if c == r || strings.HasPrefix(c, strings.TrimSuffix(r, "/")+"/") {
				return true
			}
		}
		return false
	case OpURLIn:
		s, ok := v.(string)
		if !ok {
			return false
		}
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.User != nil {
			return false
		}
		port := defaultPortOf(strings.ToLower(u.Scheme))
		if ps := u.Port(); ps != "" {
			if port, err = strconv.Atoi(ps); err != nil {
				return false
			}
		}
		for _, o := range p.origins {
			if o.scheme == strings.ToLower(u.Scheme) && o.host == strings.ToLower(u.Hostname()) && o.port == port {
				return true
			}
		}
		return false
	}
	return false
}

// matchPredicates reports whether every predicate of the rule holds, the
// first that does not, and whether an approval predicate applies.
func matchPredicates(ps []Predicate, raw json.RawMessage, now time.Time) (ok bool, failed string, approval bool) {
	var args map[string]any
	if len(ps) > 0 && len(raw) > 0 {
		_ = json.Unmarshal(raw, &args)
	}
	for i := range ps {
		p := &ps[i]
		if !p.holds(args, now) {
			if p.Arg != "" {
				return false, p.Op + " on " + p.Arg, false
			}
			return false, p.Op, false
		}
		if p.Op == OpApproval {
			approval = true
		}
	}
	return true, "", approval
}
