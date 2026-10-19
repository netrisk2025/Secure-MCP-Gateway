package packaging

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"aead.dev/minisign"
)

// RevocationsDir is the library subdirectory holding revocation entries
// (FR-14.12).
const RevocationsDir = "revocations"

// Revocation withdraws one server revision (FR-14.12). It is signed with
// the same key type as packages; any enrolled anchor may sign one, expired
// or not, because a revocation only removes trust.
type Revocation struct {
	RevocationVersion int    `json:"revocation_version"`
	ServerID          string `json:"server_id"`
	Revision          string `json:"revision"`
	Reason            string `json:"reason"`
	RevokedAt         string `json:"revoked_at"`
	SignerKeyID       string `json:"signer_key_id"`
}

var (
	serverIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	revisionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
)

// ValidID reports whether id and rev are a valid server ID and revision.
func ValidID(id, rev string) bool { return serverIDRE.MatchString(id) && revisionRE.MatchString(rev) }

// WriteRevocation writes and signs a revocation entry into the library and
// returns its path.
func WriteRevocation(library, id, rev, reason string, key minisign.PrivateKey, now time.Time) (string, error) {
	if !ValidID(id, rev) {
		return "", fmt.Errorf("invalid server ID or revision %q@%q", id, rev)
	}
	dir := filepath.Join(library, RevocationsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	r := Revocation{RevocationVersion: 1, ServerID: id, Revision: rev, Reason: reason, RevokedAt: now.UTC().Format(time.RFC3339), SignerKeyID: KeyID(key.ID())}
	path := filepath.Join(dir, id+"@"+rev+".json")
	if err := WriteJSON(path, r, 0o644); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sig := minisign.SignWithComments(key, raw, fmt.Sprintf("smcp-revocation %s@%s timestamp:%d", id, rev, now.Unix()), "revocation from smcpctl package revoke")
	return path, writeFileAtomic(path+".minisig", sig, 0o644)
}

// VerifyRevocation reads a revocation entry and checks its signature.
func VerifyRevocation(path string, keys KeyResolver) (Revocation, error) {
	var r Revocation
	raw, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	sig, err := os.ReadFile(path + ".minisig")
	if err != nil {
		return r, Wrap(ReasonRevocationInvalid, "revocation signature is missing", err)
	}
	if err := decodeStrict(raw, &r); err != nil || r.RevocationVersion != 1 || !ValidID(r.ServerID, r.Revision) {
		return r, Errf(ReasonRevocationInvalid, "revocation entry %s is not valid", filepath.Base(path))
	}
	id, err := signatureKeyID(sig)
	if err != nil {
		return r, Wrap(ReasonRevocationInvalid, "revocation signature", err)
	}
	pub, _, err := keys(id)
	if err != nil {
		return r, Wrap(ReasonSignerUnknown, "revocation signer "+KeyID(id), err)
	}
	if !minisign.Verify(pub, raw, sig) {
		return r, Errf(ReasonSignatureInvalid, "revocation signature does not verify")
	}
	return r, nil
}
