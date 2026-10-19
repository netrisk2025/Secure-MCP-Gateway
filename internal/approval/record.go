package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethan03805/secure-mcp-gateway/internal/pipeline"
)

// Approval states (FR-3.16).
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateDenied   = "denied"
	StateExpired  = "expired"
	StateConsumed = "consumed"
)

// Reason codes the Approval Service produces.
const (
	ReasonRequired = pipeline.ReasonApprovalRequired // -31002
	ReasonDenied   = "APPROVAL_DENIED"               // -31001
	ReasonExpired  = "APPROVAL_EXPIRED"              // -31002: the approval lapsed while held
	ReasonConsumed = "APPROVAL_CONSUMED"             // -31002: another identical call used it first
)

// Binding is what an approval is bound to (SR-1.18-2): the session and
// principal, the server, tool and route (public name) with their
// revisions, the canonical argument digest and the policy revision. A
// retry consumes an approval only when every field matches.
type Binding struct {
	SessionID       string `json:"session_id"`
	PrincipalID     string `json:"principal_id"`
	Server          string `json:"server"`
	Tool            string `json:"tool"`
	PublicName      string `json:"public_name"`
	ServerRevision  string `json:"server_revision"`
	ToolRevision    string `json:"tool_revision"`
	PolicyRevision  string `json:"policy_revision"`
	ArgumentsDigest string `json:"arguments_digest"`
}

// Record is one approval (D-01 approval log). It is persisted in the state
// directory and returned by the control API.
type Record struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Binding
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	URL       string    `json:"approval_url"`

	// Evidence for the approver (FR-3.18).
	Template       string          `json:"template,omitempty"`
	ManifestSource string          `json:"manifest_source,omitempty"`
	CorrelationID  string          `json:"correlation_id"`
	DecisionID     string          `json:"decision_id,omitempty"`
	DecisiveRules  []string        `json:"decisive_rules"`
	Arguments      json.RawMessage `json:"arguments"`
	// Anomaly is the Anomaly Scorer's evidence when an anomaly band
	// required the approval: band, contributing feature and z-score.
	Anomaly *pipeline.AnomalyEvidence `json:"anomaly,omitempty"`

	// Origin of the call (FR-16.8): set when it arrived on the Remote
	// Access listener, and applied to every approval event.
	Channel       string `json:"channel,omitempty"`
	ClientID      string `json:"client_id,omitempty"`
	ClientAddress string `json:"client_address,omitempty"`

	// Decision (FR-3.17).
	DecidedBy string     `json:"decided_by,omitempty"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	Comment   string     `json:"comment,omitempty"`

	// Consumption (FR-3.15, FR-3.20).
	ConsumedAt          *time.Time `json:"consumed_at,omitempty"`
	ConsumedCorrelation string     `json:"consumed_correlation_id,omitempty"`
}

// Summary is a record without its arguments, for lists, the watch stream
// and notifications.
type Summary struct {
	ID             string     `json:"id"`
	State          string     `json:"state"`
	PublicName     string     `json:"public_name"`
	Server         string     `json:"server"`
	ServerRevision string     `json:"server_revision"`
	SessionID      string     `json:"session_id"`
	PrincipalID    string     `json:"principal_id"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	URL            string     `json:"approval_url"`
	DecidedBy      string     `json:"decided_by,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	Channel        string     `json:"channel,omitempty"`
}

// Summary returns the record's summary.
func (r *Record) Summary() Summary {
	return Summary{ID: r.ID, State: r.State, PublicName: r.PublicName, Server: r.Server, ServerRevision: r.ServerRevision,
		SessionID: r.SessionID, PrincipalID: r.PrincipalID, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, URL: r.URL,
		DecidedBy: r.DecidedBy, DecidedAt: r.DecidedAt, Channel: r.Channel}
}

// live reports whether the record can still be decided or consumed.
func (r *Record) live() bool { return r.State == StatePending || r.State == StateApproved }

// Canonical returns the canonical JSON form of tool arguments and its
// SHA-256 digest ("sha256:<hex>"). Object keys are sorted, insignificant
// whitespace is removed and numbers keep their literal form; absent or
// null arguments canonicalize to {}.
func Canonical(args json.RawMessage) (json.RawMessage, string, error) {
	var v any
	if len(bytes.TrimSpace(args)) == 0 {
		v = map[string]any{}
	} else {
		dec := json.NewDecoder(bytes.NewReader(args))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return nil, "", fmt.Errorf("arguments: %w", err)
		}
		if dec.More() {
			return nil, "", fmt.Errorf("arguments: trailing data")
		}
		if v == nil {
			v = map[string]any{}
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, "", err
	}
	canon := bytes.TrimRight(b.Bytes(), "\n")
	sum := sha256.Sum256(canon)
	return json.RawMessage(canon), "sha256:" + hex.EncodeToString(sum[:]), nil
}

// bindingOf builds the binding of a call with its argument digest.
func bindingOf(c pipeline.Call, digest string) Binding {
	return Binding{SessionID: c.SessionID, PrincipalID: c.PrincipalID, Server: c.Server, Tool: c.Tool, PublicName: c.PublicName,
		ServerRevision: c.ServerRevision, ToolRevision: c.ToolRevision, PolicyRevision: c.PolicyRevision, ArgumentsDigest: digest}
}
