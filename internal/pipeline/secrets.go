package pipeline

import "context"

// SecretMatch is one span of scanned data that matched the leak
// fingerprints of a delivered secret (FR-6.10). It names the secret by its
// reference and version only; it never carries the value.
type SecretMatch struct {
	SecretRef string `json:"secretRef"`
	Version   int    `json:"version"`
	// Form is the encoding that matched: raw, base64, base64url, hex,
	// HEX, query or path.
	Form string `json:"form"`
	// Start and End delimit the matched bytes of the scanned data.
	Start int `json:"start"`
	End   int `json:"end"`
}

// SecretFingerprints is the leak-detection set the Secret Broker (E-20)
// registers with the Response Inspection Pipeline (E-11), the Request
// Inspection Pipeline (E-09) and the Observation Collector (E-29). It holds
// only keyed HMAC-SHA-256 digests of secret windows, never plaintext.
//
// Scan returns the matched spans, merged per secret. Redact returns a copy
// of data with each matched span replaced by "[REDACTED:<secretRef>]"
// (SR-6.7-1) and the matches. Len reports how many digests are registered;
// zero means nothing has been delivered and scanning can be skipped.
type SecretFingerprints interface {
	Scan(data []byte) []SecretMatch
	Redact(data []byte) ([]byte, []SecretMatch)
	Len() int
}

// HeaderGrant is a delivery-mode S1 credential binding (FR-6.6): the Egress
// Broker (E-18) inserts Header, built from Template with "{secret}" replaced
// by Value, on each authorized request from instances of Server to
// Destination. Value is plaintext owned by the injector after BindHeader
// returns; the injector must overwrite it on Withdraw.
type HeaderGrant struct {
	GrantID     string
	Server      string
	Slot        string
	Destination string
	Header      string
	Template    string
	SecretRef   string
	Version     int
	Value       []byte
}

// SecretHeaderInjector is the seam between the Secret Broker (E-20) and the
// Egress Broker (E-18) for delivery mode S1. Until an Egress Broker
// implements it, S1 bindings are denied with SECRET_MODE_UNAVAILABLE.
type SecretHeaderInjector interface {
	BindHeader(ctx context.Context, g HeaderGrant) error
	Withdraw(grantID string)
}
