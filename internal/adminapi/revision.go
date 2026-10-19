package adminapi

// Per-object revisions of the control state (SR-8.9-1).
//
// The control API keeps one sequence number that advances with every
// state-changing request that passes authentication and the role check,
// from any client, and records for each object the sequence number of its
// last change. That number is the object's revision. Every control API
// response carries the current sequence as its ETag ("<epoch>-<n>"): a read
// answered with tag n shows each object as it was at n.
//
// A browser mutation's If-Match names the tag of a read that showed the
// object it changes. The mutation passes when that object has not changed
// after the named tag, and is refused with 412 (and the current ETag)
// otherwise. A change to another object does not make the tag stale, so
// the console re-reads only when the object it is about to change was
// changed by someone else. Check and advance happen under one lock: of two
// mutations of the same object that name the same tag, only the first
// passes. The epoch is new at every start of smcpd, so tags from before a
// restart are refused.
//
// The object of a route is derived from its pattern: the path below
// /api/v1/ or /admin/v1/ up to its last wildcard (other than {action}),
// with the request's values, so "POST /api/v1/principals/{id}/suspend" for
// principal p changes object "principals/p"; a route without a wildcard is
// its own object, except the groups in objectGroups, which change one
// object together (stop and resume both change the run state). The answer
// of a mutation names its object in the X-SMCP-Object header.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ObjectHeader names, on the answer of a mutation, the object it changed
// (or would have changed).
const ObjectHeader = "X-SMCP-Object"

// objectGroups maps routes without a wildcard that change one shared object.
var objectGroups = map[string]string{
	"stop":             "gateway",
	"resume":           "gateway",
	"policy/reload":    "policy",
	"policy/revisions": "policy",
	"policy/rollback":  "policy",
	"remote/enable":    "remote",
	"remote/disable":   "remote",
}

// objectOf returns the object key of a mutation on pattern.
func objectOf(pattern string, r *http.Request) string {
	path := pattern
	if i := strings.IndexByte(path, ' '); i >= 0 {
		path = path[i+1:]
	}
	for _, p := range []string{"/api/v1/", "/admin/v1/"} {
		if strings.HasPrefix(path, p) {
			path = path[len(p):]
			break
		}
	}
	path = strings.Trim(path, "/")
	if g, ok := objectGroups[path]; ok {
		return g
	}
	segs := strings.Split(path, "/")
	last := -1
	for i, sg := range segs {
		if strings.HasPrefix(sg, "{") && strings.HasSuffix(sg, "}") && sg != "{action}" && sg != "{action...}" {
			last = i
		}
	}
	if last < 0 {
		return path
	}
	out := make([]string, 0, last+1)
	for _, sg := range segs[:last+1] {
		if strings.HasPrefix(sg, "{") && strings.HasSuffix(sg, "}") {
			name := strings.TrimSuffix(strings.Trim(sg, "{}"), "...")
			sg = "{" + r.PathValue(name) + "}"
		}
		out = append(out, sg)
	}
	return strings.Join(out, "/")
}

// Revision returns the current control-state sequence as an entity tag.
func (s *Server) Revision() string {
	return s.tag(s.rev.Load())
}

func (s *Server) tag(n uint64) string {
	return `"` + s.revEpoch + "-" + strconv.FormatUint(n, 10) + `"`
}

// ObjectRevision returns the revision of an object: the sequence number of
// its last change, 0 when it has not changed since smcpd started.
func (s *Server) ObjectRevision(key string) uint64 {
	s.revMu.Lock()
	defer s.revMu.Unlock()
	return s.changed[key]
}

// parseTag returns the sequence number an entity tag of this epoch names.
func (s *Server) parseTag(t string) (uint64, bool) {
	t = strings.TrimSpace(t)
	t = strings.TrimPrefix(t, "W/")
	if len(t) < 2 || t[0] != '"' || t[len(t)-1] != '"' {
		return 0, false
	}
	body := t[1 : len(t)-1]
	i := strings.LastIndexByte(body, '-') // the epoch may contain '-'
	if i < 0 || body[:i] != s.revEpoch {
		return 0, false
	}
	num := body[i+1:]
	n, err := strconv.ParseUint(num, 10, 64)
	return n, err == nil
}

// change records a change of key and returns the new sequence number. When
// check is set, it changes nothing and returns false unless one of the
// If-Match tags names a sequence at or after key's last change (and not
// after the current sequence).
func (s *Server) change(key, ifMatch string, check bool) (uint64, bool) {
	s.revMu.Lock()
	defer s.revMu.Unlock()
	if check {
		cur, last, ok := s.rev.Load(), s.changed[key], false
		for _, t := range strings.Split(ifMatch, ",") {
			if n, valid := s.parseTag(t); valid && n <= cur && n >= last {
				ok = true
				break
			}
		}
		if !ok {
			return cur, false
		}
	}
	n := s.rev.Add(1)
	s.changed[key] = n
	return n, true
}

// precondition applies SR-8.9-1's If-Match to browser mutations and records
// the change of every other mutation. It answers and returns false when the
// request must not proceed.
func (s *Server) precondition(w http.ResponseWriter, r *http.Request, pattern string) bool {
	if !isMutation(r.Method) || isLogout(r.URL.Path) {
		return true
	}
	key := objectOf(pattern, r)
	w.Header().Set(ObjectHeader, key)
	if _, browser := BrowserSessionOf(r); !browser {
		n, _ := s.change(key, "", false)
		w.Header().Set("ETag", s.tag(n))
		return true
	}
	im := r.Header.Get("If-Match")
	if im == "" {
		w.Header().Set("ETag", s.Revision())
		writeError(w, http.StatusPreconditionRequired, "precondition_required", "browser requests that change state must send If-Match with the ETag of a read of the object")
		return false
	}
	n, ok := s.change(key, im, true)
	w.Header().Set("ETag", s.tag(n))
	if !ok {
		writeError(w, http.StatusPreconditionFailed, "revision_stale", fmt.Sprintf("%s changed since revision %s; reload and retry", key, im))
		return false
	}
	return true
}
