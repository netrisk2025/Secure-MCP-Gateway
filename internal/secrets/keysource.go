package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/age"
)

// Key sources for the vault master key (SR-2.13-1). The master key is an
// age X25519 identity. It is never written to disk in plaintext: the
// keychain source keeps it in the macOS login Keychain; the passphrase
// source keeps it age-encrypted under a scrypt passphrase.
const (
	KeySourceAuto       = "auto"
	KeySourceKeychain   = "keychain"
	KeySourcePassphrase = "passphrase"
)

// MasterKeyFile is the passphrase-wrapped master key, under the vault
// directory.
const MasterKeyFile = "master.age"

// KeychainService is the Keychain service name of vault master keys.
const KeychainService = "dev.secure-mcp-gateway.vault"

// securityTool is the macOS Keychain command-line tool.
var securityTool = "/usr/bin/security"

// ErrLocked means the master key could not be unlocked.
var ErrLocked = errors.New("vault master key unavailable")

// KeySource stores and loads the vault master key.
type KeySource interface {
	Name() string
	// Store saves a new master key; it refuses to overwrite one.
	Store(identity string) error
	// Load returns the master key.
	Load() (string, error)
}

// KeychainAvailable reports whether the macOS Keychain tool exists.
func KeychainAvailable() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := os.Stat(securityTool)
	return err == nil
}

// ResolveKeySource maps "auto" to the strongest source the host offers.
// The Linux kernel keyring is not used: its keys do not survive a reboot,
// so it cannot hold the only copy of the master key; TPM sealing is not
// implemented. On Linux the passphrase source is used.
func ResolveKeySource(name string) (string, error) {
	switch name {
	case "", KeySourceAuto:
		if KeychainAvailable() {
			return KeySourceKeychain, nil
		}
		return KeySourcePassphrase, nil
	case KeySourceKeychain:
		if !KeychainAvailable() {
			return "", errors.New("key_source keychain needs macOS and /usr/bin/security")
		}
		return name, nil
	case KeySourcePassphrase:
		return name, nil
	}
	return "", fmt.Errorf("unknown key_source %q (auto, keychain, passphrase)", name)
}

// Keychain keeps the master key as a generic password item. The value is
// passed to the security tool on standard input, never in its arguments.
type Keychain struct {
	Account string
	// Keychain is a keychain file; empty uses the default (login) keychain.
	Keychain string
}

// Name implements KeySource.
func (Keychain) Name() string { return KeySourceKeychain }

func (k Keychain) args(a ...string) []string {
	if k.Keychain != "" {
		a = append(a, k.Keychain)
	}
	return a
}

// Store implements KeySource.
func (k Keychain) Store(identity string) error {
	if strings.ContainsAny(identity, " \t\r\n\"'\\") || strings.ContainsAny(k.Account+k.Keychain, " \t\r\n\"'\\") {
		return errors.New("keychain: unexpected characters")
	}
	if _, err := k.Load(); err == nil {
		return errors.New("keychain: a master key for this vault already exists")
	}
	// `security -i` reads commands from standard input, so the key never
	// appears in a process argument list.
	line := strings.Join(k.args("add-generic-password", "-a", k.Account, "-s", KeychainService, "-l", "secure-mcp-gateway-vault", "-w", identity), " ")
	cmd := exec.Command(securityTool, "-i")
	cmd.Stdin = strings.NewReader(line + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain: add item: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	if strings.TrimSpace(stderr.String()) != "" {
		return fmt.Errorf("keychain: add item: %s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Load implements KeySource.
func (k Keychain) Load() (string, error) {
	cmd := exec.Command(securityTool, k.args("find-generic-password", "-a", k.Account, "-s", KeychainService, "-w")...)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: keychain item %s/%s not readable: %s", ErrLocked, KeychainService, k.Account, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// Delete removes the keychain item (used by tests and by vault removal).
func (k Keychain) Delete() error {
	return exec.Command(securityTool, k.args("delete-generic-password", "-a", k.Account, "-s", KeychainService)...).Run()
}

// Passphrase keeps the master key in MasterKeyFile, encrypted with age to
// an scrypt recipient derived from the passphrase.
type Passphrase struct {
	Path       string
	Passphrase func() (string, error)
	// WorkFactor is the scrypt work factor (log2 N); 0 selects age's
	// default (18). Tests lower it.
	WorkFactor int
}

// Name implements KeySource.
func (Passphrase) Name() string { return KeySourcePassphrase }

// Store implements KeySource.
func (p Passphrase) Store(identity string) error {
	pw, err := p.Passphrase()
	if err != nil {
		return err
	}
	if len(pw) < 12 {
		return errors.New("vault passphrase must have 12 or more characters")
	}
	r, err := age.NewScryptRecipient(pw)
	if err != nil {
		return err
	}
	if p.WorkFactor > 0 {
		r.SetWorkFactor(p.WorkFactor)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, identity); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	f, err := os.OpenFile(p.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("master key file: %w", err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Load implements KeySource.
func (p Passphrase) Load() (string, error) {
	raw, err := os.ReadFile(p.Path)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLocked, err)
	}
	pw, err := p.Passphrase()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLocked, err)
	}
	id, err := age.NewScryptIdentity(pw)
	if err != nil {
		return "", err
	}
	r, err := age.Decrypt(bytes.NewReader(raw), id)
	if err != nil {
		return "", fmt.Errorf("%w: wrong passphrase or damaged %s", ErrLocked, filepath.Base(p.Path))
	}
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrLocked, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// PassphraseFromFile returns a passphrase reader for a file that must not
// be readable or writable by group or others.
func PassphraseFromFile(path string) func() (string, error) {
	return func() (string, error) {
		st, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if st.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("passphrase file %s has mode %o; it must be 0600 or stricter", path, st.Mode().Perm())
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
}
