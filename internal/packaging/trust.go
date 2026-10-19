package packaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"aead.dev/minisign"
)

// AnchorsFile is the trust anchor store under the state directory (E-22).
const AnchorsFile = "keys/trust-anchors.json"

// DefaultAnchorClasses are the risk classes an anchor may admit when the
// operator names none (FR-14.8).
var DefaultAnchorClasses = []string{"low", "moderate"}

// DefaultAnchorLifetime is the anchor expiry when the operator names none.
const DefaultAnchorLifetime = 365 * 24 * time.Hour

// Anchor is an enrolled operator minisign public key, limited to risk
// classes and an expiry (FR-14.8, SR-3-1).
type Anchor struct {
	Name      string    `json:"name"`
	KeyID     string    `json:"key_id"`
	PublicKey string    `json:"public_key"`
	Classes   []string  `json:"classes"`
	Expires   time.Time `json:"expires"`
	AddedAt   time.Time `json:"added_at"`
	AddedBy   string    `json:"added_by,omitempty"`
}

// Anchors is the trust anchor store.
type Anchors struct {
	Version int      `json:"version"`
	Anchors []Anchor `json:"anchors"`
	path    string
}

// LoadAnchors reads the store under stateDir; a missing file is an empty
// store.
func LoadAnchors(stateDir string) (*Anchors, error) {
	a := &Anchors{Version: 1, path: filepath.Join(stateDir, AnchorsFile)}
	raw, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, a); err != nil {
		return nil, fmt.Errorf("%s: %w", a.path, err)
	}
	return a, nil
}

// Save writes the store (mode 0600).
func (a *Anchors) Save() error {
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	return WriteJSON(a.path, a, 0o600)
}

var anchorName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Add enrolls a public key (FR-14.8). Classes default to low and
// moderate; expires must be in the future.
func (a *Anchors) Add(name string, pubRaw []byte, classes []string, expires, now time.Time, actor string) (Anchor, error) {
	pub, err := ParsePublicKey(pubRaw)
	if err != nil {
		return Anchor{}, fmt.Errorf("public key: %w", err)
	}
	if !anchorName.MatchString(name) {
		return Anchor{}, fmt.Errorf("anchor name %q must be 1 to 64 characters of A-Z a-z 0-9 . _ -", name)
	}
	if len(classes) == 0 {
		classes = DefaultAnchorClasses
	}
	for _, c := range classes {
		if !slices.Contains(RiskClasses, c) {
			return Anchor{}, fmt.Errorf("risk class %q is not one of %v", c, RiskClasses)
		}
	}
	if !expires.After(now) {
		return Anchor{}, errors.New("the anchor expiry must be in the future")
	}
	id := KeyID(pub.ID())
	for _, x := range a.Anchors {
		if x.KeyID == id {
			return Anchor{}, fmt.Errorf("key %s is already enrolled as %q", id, x.Name)
		}
		if x.Name == name {
			return Anchor{}, fmt.Errorf("an anchor named %q exists", name)
		}
	}
	an := Anchor{Name: name, KeyID: id, PublicKey: pub.String(), Classes: slices.Clone(classes), Expires: expires.UTC(), AddedAt: now.UTC(), AddedBy: actor}
	slices.Sort(an.Classes)
	a.Anchors = append(a.Anchors, an)
	return an, nil
}

// Remove deletes an anchor by name or key ID.
func (a *Anchors) Remove(nameOrID string) bool {
	n := len(a.Anchors)
	a.Anchors = slices.DeleteFunc(a.Anchors, func(x Anchor) bool { return x.Name == nameOrID || x.KeyID == nameOrID })
	return len(a.Anchors) != n
}

// Resolver resolves signer keys against the enrolled anchors.
func (a *Anchors) Resolver() KeyResolver {
	return func(id uint64) (minisign.PublicKey, *Anchor, error) {
		want := KeyID(id)
		for i := range a.Anchors {
			if a.Anchors[i].KeyID != want {
				continue
			}
			pub, err := ParsePublicKey([]byte(a.Anchors[i].PublicKey))
			if err != nil {
				return minisign.PublicKey{}, nil, fmt.Errorf("anchor %s: %w", a.Anchors[i].Name, err)
			}
			an := a.Anchors[i]
			return pub, &an, nil
		}
		return minisign.PublicKey{}, nil, ErrUnknownKey
	}
}
