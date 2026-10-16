// Package ids issues the identifiers every element attaches to its records.
package ids

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/google/uuid"
)

// New returns a time-ordered UUIDv7 string (FR-4.2 for correlation IDs; used
// for decision, session, event and segment IDs as well).
func New() string {
	id, err := uuid.NewV7()
	if err != nil {
		// uuid.NewV7 only fails when the CSPRNG fails, which is unrecoverable.
		panic("uuid.NewV7: " + err.Error())
	}
	return id.String()
}

// Secret returns a URL-safe token built from 32 bytes (256 bits) of CSPRNG
// output, as SR-2.3-1 requires for tokens, codes and secrets.
func Secret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
