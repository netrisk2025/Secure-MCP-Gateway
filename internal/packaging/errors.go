// Package packaging implements operator self-curation of local MCP servers
// (SRS FR-14, ARCH §18.1): building a package from a pinned artifact
// (npm, PyPI, OCI or a local binary), generating its manifest from a live
// tools/list, writing the provenance statement and package index, signing
// and verifying the index with minisign, and the operator trust anchors
// that scope which risk classes a key may admit.
//
// The Library Trust Verifier (E-13) and Local Server Registry (E-14) that
// import and run packages are in internal/library; this package holds the
// formats and the offline operations both smcpctl and smcpd use.
package packaging

import (
	"errors"
	"fmt"
)

// Reason codes. Each refusal names one; they are documented in
// docs/packaging.md and appear in import receipts and evidence events.
const (
	ReasonUnpinned           = "UNPINNED_REFERENCE"         // FR-14.2
	ReasonDigestMismatch     = "DIGEST_MISMATCH"            // FR-14.1, FR-14.7, SR-3-2
	ReasonFetchFailed        = "FETCH_FAILED"               // FR-14.1
	ReasonProbeFailed        = "PROBE_FAILED"               // FR-14.3
	ReasonEraUnsupported     = "ERA_UNSUPPORTED"            // FR-14.3, FR-5.16
	ReasonIndexMissing       = "PACKAGE_INDEX_MISSING"      // FR-5.2
	ReasonSignatureMissing   = "PACKAGE_SIGNATURE_MISSING"  // FR-5.2
	ReasonManifestMissing    = "PACKAGE_MANIFEST_MISSING"   // FR-5.2
	ReasonProvenanceMissing  = "PACKAGE_PROVENANCE_MISSING" // FR-5.2
	ReasonArtifactMissing    = "PACKAGE_ARTIFACT_MISSING"   // FR-5.2
	ReasonSignerKeyIDMissing = "SIGNER_KEY_ID_MISSING"      // FR-5.2
	ReasonIndexInvalid       = "PACKAGE_INDEX_INVALID"      // FR-5.2
	ReasonSignatureInvalid   = "SIGNATURE_INVALID"          // SR-3-1, FR-14.7
	ReasonSignerUnknown      = "SIGNER_UNKNOWN"             // SR-3-1
	ReasonAnchorExpired      = "ANCHOR_EXPIRED"             // SR-3-1
	ReasonAnchorScope        = "ANCHOR_SCOPE"               // SR-3-1, FR-14.8
	ReasonManifestSchema     = "MANIFEST_SCHEMA"            // FR-14.11
	ReasonManifestVersion    = "MANIFEST_VERSION_UNSUPPORTED"
	ReasonSourceEvidence     = "SOURCE_EVIDENCE_MISSING" // SR-3.1-1
	ReasonProvenanceBinding  = "PROVENANCE_BINDING"      // SR-3.2-1
	ReasonRemoteBackend      = "REMOTE_BACKEND_UNSUPPORTED"
	ReasonUnpinnedLaunch     = "UNPINNED_LAUNCH" // SR-3.6-1
	ReasonKeyOnCommandLine   = "KEY_ON_COMMAND_LINE"
	ReasonRevocationInvalid  = "REVOCATION_INVALID" // FR-14.12
)

// Error is a refusal with a reason code.
type Error struct {
	Reason string
	Msg    string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Reason, e.Msg, e.Err)
	}
	return e.Reason + ": " + e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// Errf builds an Error.
func Errf(reason, format string, args ...any) *Error {
	return &Error{Reason: reason, Msg: fmt.Sprintf(format, args...)}
}

// Wrap builds an Error around a cause.
func Wrap(reason, msg string, err error) *Error {
	return &Error{Reason: reason, Msg: msg, Err: err}
}

// ReasonOf returns the reason code of err, or "" when it carries none.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}
