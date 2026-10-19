// Package pipeline defines the extension points of the enforcement pipeline
// (FR-4.3) that later elements plug into, each with a default
// implementation that preserves the Gateway's current behavior:
//
//	Approver        E-07 Approval Service       default RefuseApprover (-31002)
//	RequestFilter   E-09 Request Inspection     default chain: schema-validate
//	ResponseFilter  E-11 Response Inspection    default chain: empty
//	Launcher        E-15/E-16 Runtime, Sandbox  default SubprocessLauncher (unconfined); internal/sandbox is the confining one
//	ManifestSource  E-13/E-14 Trust, Registry   default LiveManifest (unverified)
//	SecretBroker    E-20 Secret Broker          default NoSecrets
//	Capabilities    E-12 -> E-10 launch caps    concrete one-use ledger
//
// The package depends only on the policy and MCP SDK types, so elements can
// implement these interfaces without importing the edge or backend
// packages. internal/README.md maps each seam to the element and agent that
// fills it.
package pipeline

import (
	"github.com/ethan03805/secure-mcp-gateway/internal/policy"
)

// AnomalyEvidence is the Anomaly Scorer's evidence for an approval
// obligation it added (FR-3.18): the band of the call, the feature that
// contributed most and that feature's z-score, the baseline snapshot and
// the baseline context. A call whose context has no baseline has band
// "uncharacterized" and no feature.
type AnomalyEvidence struct {
	Band       string  `json:"band"`
	Feature    string  `json:"contributing_feature,omitempty"`
	ZScore     float64 `json:"z_score"`
	SnapshotID string  `json:"snapshot_id,omitempty"`
	Context    string  `json:"context,omitempty"`
}

// Call is what every stage knows about one tools/call after the decision.
// Stages must treat it as read-only, except RequireApproval,
// ApprovalReason, AnomalySnapshot and Anomaly.
type Call struct {
	CorrelationID  string
	SessionID      string
	PrincipalID    string
	Template       string
	Purpose        string
	Project        string
	EndUser        string
	Server         string // server alias
	Tool           string // backend tool name
	PublicName     string
	ServerRevision string
	ToolRevision   string
	ManifestSource string // "live" (unverified) or the verified manifest source
	DecisionID     string
	PolicyRevision string
	Obligations    policy.Obligations
	DecisiveRules  []string // rule IDs that decided the permit (FR-3.18)
	InputSchema    any
	OutputSchema   any
	// Inspection collects the filter runs of this call across both chains
	// (findings, tags, timing). RunRequest and RunResponse create it when
	// nil; later stages read it through its methods.
	Inspection *Inspection
	// RequireApproval may be set by a request filter to require approval
	// (E-07) although the decision did not. It can only add the obligation
	// (restrict-only, SR-1.12-2); the Anomaly Scorer's synchronous
	// obligation (E-31, FR-4.15) uses it. ApprovalReason names the cause.
	RequireApproval bool
	ApprovalReason  string
	// AnomalySnapshot is the baseline snapshot ID of the score that set
	// RequireApproval; the decision record carries it (SR-1.12-3).
	AnomalySnapshot string
	// Anomaly is the score evidence of an anomaly approval obligation:
	// the band, the contributing feature and its z-score, shown to the
	// approver (FR-3.18). Nil when the obligation has another cause.
	Anomaly *AnomalyEvidence
	// Remote origin (FR-16.8): set for calls received on the Remote Access
	// listener; stages that write evidence copy them onto their events.
	Channel       string
	ClientID      string
	ClientAddress string
	// Self-asserted request metadata: a valid W3C traceparent from the
	// request _meta (FR-1.44) and the client's
	// io.modelcontextprotocol/clientInfo as "name/version" (FR-1.45).
	// They are observation attributes only: the decision request does not
	// carry them, and nothing from the harness _meta is sent southbound.
	TraceParent string
	ClientInfo  string
}
