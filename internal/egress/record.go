package egress

import (
	"net/http"
	"slices"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
	"github.com/ethan03805/secure-mcp-gateway/internal/ids"
	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Reason codes of egress refusals and terminations. docs/egress.md lists
// each with the operator's next action.
const (
	ReasonNoGrant            = "EGRESS_NO_GRANT"
	ReasonMethod             = "EGRESS_METHOD_REFUSED"
	ReasonBadRequest         = "EGRESS_BAD_REQUEST"
	ReasonAddressRefused     = "EGRESS_ADDRESS_REFUSED"
	ReasonDNSFailed          = "EGRESS_DNS_FAILED"
	ReasonSNIMismatch        = "EGRESS_SNI_MISMATCH"
	ReasonNotTLS             = "EGRESS_NOT_TLS"
	ReasonRateLimited        = "EGRESS_RATE_LIMITED"
	ReasonByteRate           = "EGRESS_BYTE_RATE_LIMITED"
	ReasonRequestTooLarge    = "EGRESS_REQUEST_TOO_LARGE"
	ReasonResponseTooLarge   = "EGRESS_RESPONSE_TOO_LARGE"
	ReasonTimeout            = "EGRESS_TIMEOUT"
	ReasonUpstream           = "EGRESS_UPSTREAM_FAILED"
	ReasonRedirect           = "EGRESS_REDIRECT_REFUSED"
	ReasonEvidenceFailed     = "EGRESS_EVIDENCE_UNAVAILABLE"
	ReasonPublicFetchProfile = "EGRESS_PUBLIC_FETCH_PROFILE"
	ReasonCapabilityRequired = "EGRESS_CAPABILITY_REQUIRED"
	ReasonCapabilityInvalid  = "EGRESS_CAPABILITY_INVALID"
	ReasonCapabilityReplayed = "EGRESS_CAPABILITY_REPLAYED"
	ReasonCapabilityMismatch = "EGRESS_CAPABILITY_MISMATCH"
)

// reasonStatus is the HTTP status the instance receives for each refusal.
var reasonStatus = map[string]int{
	ReasonNoGrant:            http.StatusForbidden,
	ReasonMethod:             http.StatusForbidden,
	ReasonBadRequest:         http.StatusBadRequest,
	ReasonAddressRefused:     http.StatusForbidden,
	ReasonDNSFailed:          http.StatusBadGateway,
	ReasonSNIMismatch:        http.StatusForbidden,
	ReasonNotTLS:             http.StatusForbidden,
	ReasonRateLimited:        http.StatusTooManyRequests,
	ReasonByteRate:           http.StatusTooManyRequests,
	ReasonRequestTooLarge:    http.StatusRequestEntityTooLarge,
	ReasonResponseTooLarge:   http.StatusBadGateway,
	ReasonTimeout:            http.StatusGatewayTimeout,
	ReasonUpstream:           http.StatusBadGateway,
	ReasonRedirect:           http.StatusForbidden,
	ReasonEvidenceFailed:     http.StatusServiceUnavailable,
	ReasonPublicFetchProfile: http.StatusForbidden,
	ReasonCapabilityRequired: http.StatusForbidden,
	ReasonCapabilityInvalid:  http.StatusForbidden,
	ReasonCapabilityReplayed: http.StatusForbidden,
	ReasonCapabilityMismatch: http.StatusForbidden,
}

// Operation modes.
const (
	ModeConnect  = "connect"
	ModeHTTP     = "http"
	ModeEndpoint = "endpoint"
)

// Decisions.
const (
	DecisionAllowed = "allowed"
	DecisionDenied  = "denied"
)

// Record is the evidence of one egress operation. It is the Detail of the
// journal event and the row of the control API's connection list.
type Record struct {
	ID           string    `json:"id"`
	Time         time.Time `json:"time"`
	Instance     string    `json:"instance"`
	Server       string    `json:"server"`
	Mode         string    `json:"mode"`
	Method       string    `json:"method,omitempty"`
	Host         string    `json:"host,omitempty"`
	Port         int       `json:"port,omitempty"`
	Path         string    `json:"path,omitempty"`
	SNI          string    `json:"sni,omitempty"`
	Grant        string    `json:"grant,omitempty"`
	Resolved     []string  `json:"resolved,omitempty"`
	Address      string    `json:"address,omitempty"`
	AddressClass string    `json:"address_class,omitempty"`
	Redirects    int       `json:"redirects,omitempty"`
	Injected     []string  `json:"injected_headers,omitempty"` // S1 header names, never values
	// Capability is the state of the one-use capability the operation
	// presented (SR-5.16-1): consumed, missing, invalid, replayed or
	// mismatch; empty when capabilities are not required. The call it
	// was minted for is named by the three IDs below (never the token).
	Capability     string `json:"capability,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	DecisionID     string `json:"decision_id,omitempty"`
	PolicyRevision string `json:"policy_revision,omitempty"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason,omitempty"`
	Detail         string `json:"detail,omitempty"`
	Status         int    `json:"status,omitempty"`
	BytesUp        int64  `json:"bytes_up"`
	BytesDown      int64  `json:"bytes_down"`
	DurationMS     int64  `json:"duration_ms"`
	// Bounds are the request size, response size and duration limits
	// applied to the operation once authorized (FR-5.38, bounds.go).
	Bounds     *Bounds `json:"bounds,omitempty"`
	start      time.Time
	obligation pipeline.EgressLimits // of the call whose capability was spent
}

func (b *Broker) newRecord(in *instance, mode, method string) *Record {
	now := b.o.Now()
	return &Record{ID: ids.New(), Time: now.UTC(), start: now, Instance: in.id, Server: in.alias, Mode: mode, Method: method}
}

// authorized writes the "authorized" event before any byte is forwarded.
// A failure means the operation must be refused (fail closed).
func (b *Broker) authorized(r *Record) error {
	r.Decision = DecisionAllowed
	cp := *r
	return b.o.Evidence.Record(audit.Event{Class: "egress", Origin: Origin, Phase: audit.PhaseAuthorized, Outcome: "allow",
		CorrelationID: r.CorrelationID, DecisionID: r.DecisionID, PolicyRevision: r.PolicyRevision, PolicyStatus: "evaluated", Detail: cp})
}

// finish writes the terminal event of an operation and keeps the record
// for the control API. reason is empty for a normal completion.
func (b *Broker) finish(r *Record, reason, detail string) {
	r.DurationMS = b.o.Now().Sub(r.start).Milliseconds()
	phase, outcome := audit.PhaseCompleted, "completed"
	if r.Decision == "" {
		r.Decision = DecisionDenied
	}
	if reason != "" {
		r.Reason, r.Detail = reason, detail
		if r.Decision == DecisionDenied {
			phase, outcome = audit.PhaseDenied, "deny"
		} else {
			phase, outcome = audit.PhaseFailed, "terminated"
		}
	}
	cp := *r
	if err := b.o.Evidence.Record(audit.Event{Class: "egress", Origin: Origin, Phase: phase, Outcome: outcome, ReasonCode: reason,
		CorrelationID: r.CorrelationID, DecisionID: r.DecisionID, PolicyRevision: r.PolicyRevision, PolicyStatus: "evaluated", Detail: cp}); err != nil {
		b.o.Log.Error("egress evidence write failed", "err", err, "operation", r.ID)
	}
	b.keep(cp)
}

func (b *Broker) keep(r Record) {
	if b.o.Recent == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.recent) < b.o.Recent {
		b.recent = append(b.recent, r)
		return
	}
	b.recent[b.next] = r
	b.next = (b.next + 1) % b.o.Recent
	b.full = true
}

// Recent returns kept records, newest first.
func (b *Broker) Recent() []Record {
	b.mu.Lock()
	out := make([]Record, 0, len(b.recent))
	if b.full {
		out = append(out, b.recent[b.next:]...)
		out = append(out, b.recent[:b.next]...)
	} else {
		out = append(out, b.recent...)
	}
	b.mu.Unlock()
	slices.Reverse(out)
	return out
}

// refuse answers the instance with the reason code and records the
// refusal.
func (b *Broker) refuse(w http.ResponseWriter, r *Record, reason, detail string) {
	st, ok := reasonStatus[reason]
	if !ok {
		st = http.StatusForbidden
	}
	r.Status = st
	b.finish(r, reason, detail)
	w.Header().Set(ReasonHeader, reason)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(st)
	// #nosec G705 -- plain text with nosniff to a server instance, not a browser page
	_, _ = w.Write([]byte("egress refused: " + reason + ": " + detail + "\n"))
}
