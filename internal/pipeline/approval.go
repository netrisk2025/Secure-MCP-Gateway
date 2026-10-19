package pipeline

import (
	"context"
	"encoding/json"
	"time"
)

// ApprovalOutcome is the result of an approval request.
type ApprovalOutcome string

const (
	// Approved: a person approved this call; the pipeline continues.
	Approved ApprovalOutcome = "approved"
	// Denied: a person denied this call; the pipeline refuses it with
	// Gateway error -31001 and reason APPROVAL_DENIED.
	Denied ApprovalOutcome = "denied"
	// Pending: no decision within the hold bound (or no approval service);
	// the pipeline refuses with -31002 and returns RetryText and ConsoleURL
	// so the person can approve and the agent can retry.
	Pending ApprovalOutcome = "pending"
)

// ApprovalRequest asks for a person's decision on one call (FR-3.14).
//
// Hold semantics: the Approver may park the call for up to Hold while it
// waits for a decision, calling Progress periodically (at least every 10
// seconds) so the harness sees the call is alive. Progress is best effort
// and may be a no-op when the harness gave no progress token or the
// response mode cannot carry notifications. When Hold elapses, or ctx ends,
// the Approver returns Pending.
type ApprovalRequest struct {
	Call      Call
	Arguments json.RawMessage
	Hold      time.Duration
	Progress  func(message string)
}

// ApprovalResult is the Approver's answer. ApprovalID and Approver identify
// the approval record for evidence; RetryText is plain-language guidance
// shown to the agent when the outcome is Pending; ConsoleURL deep-links to
// the pending approval and ExpiresAt is when it lapses (CP-17), both
// reported in the -31002 data (FR-3.22).
type ApprovalResult struct {
	Outcome    ApprovalOutcome
	ApprovalID string
	Approver   string
	ReasonCode string
	RetryText  string
	ConsoleURL string
	ExpiresAt  time.Time
}

// Approver is the Approval Service seam (E-07). An error is treated as
// Pending with reason APPROVAL_UNAVAILABLE (fail closed).
type Approver interface {
	Request(ctx context.Context, req ApprovalRequest) (ApprovalResult, error)
}

// ReasonApprovalRequired is the reason code of a Pending refusal.
const ReasonApprovalRequired = "APPROVAL_REQUIRED"

// RefuseApprover is the default Approver: no approval service runs, so every
// approval-obligated call is refused immediately with -31002.
type RefuseApprover struct{}

// Request implements Approver.
func (RefuseApprover) Request(context.Context, ApprovalRequest) (ApprovalResult, error) {
	return ApprovalResult{
		Outcome:    Pending,
		ReasonCode: ReasonApprovalRequired,
		RetryText:  "This tool call needs a person's approval, and no approval service is running on this Gateway. Ask the operator to approve the call or change the policy, then retry.",
	}, nil
}
