package packaging

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"aead.dev/minisign"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/scrypt"
)

type hashWriter struct{ hash.Hash }

func newHash() hashWriter        { return hashWriter{sha256.New()} }
func (h hashWriter) hex() string { return hex.EncodeToString(h.Sum(nil)) }

// KeyID formats a minisign key ID as 16 uppercase hex digits.
func KeyID(id uint64) string { return fmt.Sprintf("%016X", id) }

// ParseKeyID parses a key ID written by KeyID (leading zeros optional).
func ParseKeyID(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(s), 16, 64)
}

// GenerateKey creates a minisign key pair. When passphrase is non-empty
// the secret key is encrypted with it (scrypt, as minisign does);
// otherwise it is written unencrypted and must be protected by file mode.
// It returns the secret and public key file contents.
func GenerateKey(passphrase string) (secret, public []byte, id string, err error) {
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	if passphrase != "" {
		secret, err = minisign.EncryptKey(passphrase, priv)
	} else {
		secret, err = priv.MarshalText()
	}
	if err != nil {
		return nil, nil, "", err
	}
	public, err = pub.MarshalText()
	if err != nil {
		return nil, nil, "", err
	}
	return secret, append(public, '\n'), KeyID(pub.ID()), nil
}

// SecretKeyEncrypted reports whether a secret key file is encrypted.
func SecretKeyEncrypted(raw []byte) bool { return minisign.IsEncrypted(raw) }

// ParseSecretKey decodes a secret key file, decrypting it with passphrase
// when it is encrypted.
func ParseSecretKey(raw []byte, passphrase string) (minisign.PrivateKey, error) {
	if minisign.IsEncrypted(raw) {
		return minisign.DecryptKey(passphrase, raw)
	}
	var k minisign.PrivateKey
	if err := k.UnmarshalText(raw); err != nil {
		return minisign.PrivateKey{}, err
	}
	return k, nil
}

// ParsePublicKey decodes a minisign public key file or the bare base64
// key line.
func ParsePublicKey(raw []byte) (minisign.PublicKey, error) {
	var k minisign.PublicKey
	err := k.UnmarshalText([]byte(strings.TrimSpace(string(raw))))
	return k, err
}

// Fingerprint returns what an administrator compares before enrolling a
// trust anchor (FR-7.10): the minisign key ID (the value minisign prints)
// and the SHA-256 of the canonical key line, in lowercase hex.
func Fingerprint(raw []byte) (keyID, sha string, err error) {
	pub, err := ParsePublicKey(raw)
	if err != nil {
		return "", "", fmt.Errorf("not a minisign public key: %w", err)
	}
	sum := sha256.Sum256([]byte(pub.String()))
	return KeyID(pub.ID()), hex.EncodeToString(sum[:]), nil
}

// Sign writes the signer key ID into the package index, then signs the
// index with key (FR-14.6). The trusted comment names the package.
func Sign(dir string, key minisign.PrivateKey, now time.Time) error {
	raw, err := os.ReadFile(filepath.Join(dir, IndexFile))
	if err != nil {
		return Wrap(ReasonIndexMissing, "package index", err)
	}
	var ix Index
	if err := decodeStrict(raw, &ix); err != nil {
		return Wrap(ReasonIndexInvalid, "package index", err)
	}
	ix.SignerKeyID = KeyID(key.ID())
	if err := WriteJSON(filepath.Join(dir, IndexFile), ix, 0o644); err != nil {
		return err
	}
	if raw, err = os.ReadFile(filepath.Join(dir, IndexFile)); err != nil {
		return err
	}
	trusted := fmt.Sprintf("smcp-package %s@%s timestamp:%d", ix.ServerID, ix.Revision, now.Unix())
	sig := minisign.SignWithComments(key, raw, trusted, "signature from smcpctl package sign")
	return writeFileAtomic(filepath.Join(dir, SignatureFile), sig, 0o644)
}

// signatureKeyID returns the key ID named in a minisign signature.
func signatureKeyID(sig []byte) (uint64, error) {
	var s minisign.Signature
	if err := s.UnmarshalText(sig); err != nil {
		return 0, err
	}
	return s.KeyID, nil
}

// KeyResolver finds the public key for a signer key ID. It returns the
// anchor when the key is an enrolled trust anchor, or nil for a key given
// directly (smcpctl package verify --pubkey).
type KeyResolver func(keyID uint64) (minisign.PublicKey, *Anchor, error)

// ErrUnknownKey is returned by a KeyResolver for an unknown key.
var ErrUnknownKey = errors.New("unknown signer key")

// PublicKeyResolver resolves only the given key.
func PublicKeyResolver(pub minisign.PublicKey) KeyResolver {
	return func(id uint64) (minisign.PublicKey, *Anchor, error) {
		if id != pub.ID() {
			return minisign.PublicKey{}, nil, ErrUnknownKey
		}
		return pub, nil, nil
	}
}

// VerifyOptions configure Verify.
type VerifyOptions struct {
	Keys KeyResolver
	Now  time.Time
}

// Verify checks a package directory offline (FR-14.7, SR-3-1, FR-5.2):
// every component present, the minisign signature over the index under a
// resolved key, the listed digests, the manifest schema, the provenance
// binding and, for a trust anchor, its expiry and risk-class scope. The
// first failed check is returned with its reason code.
func Verify(dir string, o VerifyOptions) (*Package, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	p, err := readPackage(dir)
	if err != nil {
		return nil, err
	}
	sigID, err := signatureKeyID(p.Signature)
	if err != nil {
		return nil, Wrap(ReasonSignatureInvalid, "signature file is not a minisign signature", err)
	}
	ixID, err := ParseKeyID(p.Index.SignerKeyID)
	if err != nil || ixID != sigID {
		return nil, Errf(ReasonSignatureInvalid, "the index names signer %s but the signature was made by %s", p.Index.SignerKeyID, KeyID(sigID))
	}
	pub, anchor, err := o.Keys(sigID)
	if err != nil {
		return nil, Wrap(ReasonSignerUnknown, "signer "+KeyID(sigID)+" is not an enrolled trust anchor or the given key", err)
	}
	if !minisign.Verify(pub, p.IndexRaw, p.Signature) {
		return nil, Errf(ReasonSignatureInvalid, "the signature over %s does not verify under key %s", IndexFile, KeyID(sigID))
	}
	if anchor != nil && !o.Now.Before(anchor.Expires) {
		return nil, Errf(ReasonAnchorExpired, "trust anchor %s expired at %s", anchor.Name, anchor.Expires.Format(time.RFC3339))
	}
	if err := p.checkDigests(); err != nil {
		return nil, err
	}
	if err := p.loadContents(); err != nil {
		return nil, err
	}
	if anchor != nil {
		if r := p.Manifest.HighestRisk(); !slices.Contains(anchor.Classes, r) {
			return nil, Errf(ReasonAnchorScope, "trust anchor %s may admit risk classes %v, not %s", anchor.Name, anchor.Classes, r)
		}
	}
	return p, nil
}

// EncryptSecretKeyCost encrypts a secret key in the minisign format with
// the given scrypt cost (ops, mem as minisign and libsodium define them).
// GenerateKey uses minisign's "sensitive" cost (1 GiB); a lower cost is for
// tests and for keys that are protected otherwise.
func EncryptSecretKeyCost(passphrase string, key minisign.PrivateKey, ops, mem uint64) ([]byte, error) {
	text, err := key.MarshalText()
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.SplitN(string(text), "\n", 2)[1]))
	if err != nil || len(raw) != 158 {
		return nil, errors.New("unexpected secret key encoding")
	}
	plaintext := raw[54:126] // key ID || Ed25519 private key
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	n, r, p := scryptParams(ops, mem)
	stream, err := scrypt.Key([]byte(passphrase), salt[:], n, r, p, 104)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 2+72)
	binary.LittleEndian.PutUint16(msg, minisign.EdDSA)
	copy(msg[2:], plaintext)
	sum := blake2b.Sum256(msg)
	ct := append(append([]byte(nil), plaintext...), sum[:]...)
	for i := range ct {
		ct[i] ^= stream[i]
	}
	out := make([]byte, 158)
	binary.LittleEndian.PutUint16(out[0:], minisign.EdDSA)
	binary.LittleEndian.PutUint16(out[2:], 0x6353) // scrypt
	binary.LittleEndian.PutUint16(out[4:], 0x3242) // BLAKE2b
	copy(out[6:38], salt[:])
	binary.LittleEndian.PutUint64(out[38:], ops)
	binary.LittleEndian.PutUint64(out[46:], mem)
	copy(out[54:], ct)
	return []byte("untrusted comment: minisign encrypted secret key\n" + base64.StdEncoding.EncodeToString(out)), nil
}

// scryptParams is minisign's conversion of (ops, mem) to scrypt (N, r, p);
// it must match the library's so DecryptKey derives the same keystream.
func scryptParams(ops, mem uint64) (n, r, p int) {
	const minOps, maxRP = 1 << 15, 0x3fffffff
	if ops < minOps {
		ops = minOps
	}
	if ops < mem/32 {
		r, p = 8, 1
		for i := 1; i < 63; i++ {
			if n = 1 << i; uint64(n) > (ops / (8 * uint64(r))) {
				break
			}
		}
	} else {
		r = 8
		for i := 1; i < 63; i++ {
			if n = 1 << i; uint64(n) > (mem / (256 * uint64(r))) {
				break
			}
		}
		if rp := (ops / 4) / uint64(n); rp < maxRP {
			p = int(rp) / r //nolint:gosec // rp < maxRP
		} else {
			p = maxRP / r
		}
	}
	return n, r, p
}
