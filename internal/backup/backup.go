// Package backup writes and restores the encrypted backup archive (D-15) of
// `smcpctl backup` and `smcpctl restore` (FR-17.6, SR-7.7-1, SR-7.8-1).
//
// An archive is a tar stream encrypted with age, either to an operator
// passphrase (scrypt) or to one or more age X25519 recipients; an
// unencrypted archive is never written. Inside:
//
//	state/...           the state directory: evidence journal and anchor,
//	                    keys, TLS CA and listener certificates (trust
//	                    anchors), the vault, registry and policy store
//	                    directories when present; log/ is left out
//	config/<name>       the configuration file
//	policy/<name>       the active policy file
//	optional/<name>/... optional parts (Observation Store copy, graph dump)
//	manifest.json       format, time, installation ID, components and the
//	                    SHA-256 and size of every other entry
//
// The archive file's own SHA-256 is written next to it as <archive>.sha256
// and recorded in <dir>/index.json and in the evidence journal.
package backup

import (
	"archive/tar"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/ethan03805/secure-mcp-gateway/internal/audit"
)

// Format is the manifest format identifier.
const Format = "smcp-backup-v1"

// ErrUnencrypted is returned when neither a passphrase nor a recipient is
// given (FR-17.6).
var ErrUnencrypted = errors.New("refusing to write an unencrypted backup: give a passphrase or an age recipient")

// Encryption selects how the archive is encrypted. Exactly one of the two
// must be set.
type Encryption struct {
	Passphrase string
	Recipients []string // age1... public keys
	// WorkFactor overrides the scrypt work factor (log2 N); tests only.
	WorkFactor int
}

// Check reports whether the encryption settings can produce an archive:
// ErrUnencrypted when neither is set, or a parse error.
func (e Encryption) Check() error {
	_, err := e.recipients()
	return err
}

func (e Encryption) recipients() ([]age.Recipient, error) {
	switch {
	case e.Passphrase != "" && len(e.Recipients) > 0:
		return nil, errors.New("give a passphrase or recipients, not both (age allows a passphrase only on its own)")
	case e.Passphrase != "":
		r, err := age.NewScryptRecipient(e.Passphrase)
		if err != nil {
			return nil, err
		}
		if e.WorkFactor > 0 {
			r.SetWorkFactor(e.WorkFactor)
		}
		return []age.Recipient{r}, nil
	case len(e.Recipients) > 0:
		rs, err := age.ParseRecipients(strings.NewReader(strings.Join(e.Recipients, "\n")))
		if err != nil {
			return nil, fmt.Errorf("age recipient: %w", err)
		}
		return rs, nil
	}
	return nil, ErrUnencrypted
}

// Decryption opens an archive: a passphrase or an age identity file.
type Decryption struct {
	Passphrase   string
	IdentityFile string
}

func (d Decryption) identities() ([]age.Identity, error) {
	switch {
	case d.Passphrase != "":
		id, err := age.NewScryptIdentity(d.Passphrase)
		if err != nil {
			return nil, err
		}
		return []age.Identity{id}, nil
	case d.IdentityFile != "":
		f, err := os.Open(d.IdentityFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return age.ParseIdentities(f)
	}
	return nil, errors.New("give the backup passphrase or an age identity file")
}

// Spec names what goes into an archive.
type Spec struct {
	StateDir   string
	ConfigPath string
	PolicyPath string
	// Optional adds named optional parts (a file or directory each), for
	// example "observations" or "graph-dump".
	Optional       map[string]string
	InstallationID string
	Version        string
	Encryption     Encryption
	Now            func() time.Time
}

// excluded state subdirectories: the diagnostic log is not state, and
// backups never contain backups.
var excluded = map[string]bool{"log": true, "backups": true}

// excludedDirs are derived state directories left out of a backup: the
// package library's unpacked artifact trees and per-server work
// directories are re-created from the content-addressed artifacts
// (internal/library), and a tar entry cannot keep their executable bits.
var excludedDirs = map[string]bool{"packages/unpacked": true, "packages/work": true}

// FileEntry is one archived file.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// Manifest describes an archive.
type Manifest struct {
	Format         string      `json:"format"`
	CreatedAt      time.Time   `json:"created_at"`
	InstallationID string      `json:"installation_id,omitempty"`
	Version        string      `json:"version,omitempty"`
	Components     []string    `json:"components"`
	Files          []FileEntry `json:"files"`
}

// Has reports whether the manifest lists a component.
func (m Manifest) Has(c string) bool {
	for _, x := range m.Components {
		if x == c {
			return true
		}
	}
	return false
}

// components derives the component list of SR-7.7-1 from what is present.
func components(files []FileEntry, optional map[string]string) []string {
	has := func(prefix string) bool {
		for _, f := range files {
			if strings.HasPrefix(f.Path, prefix) {
				return true
			}
		}
		return false
	}
	var out []string
	for _, c := range []struct{ name, prefix string }{
		{"configuration", "config/"},
		{"policy_store", "state/policy/"}, // the signed Policy Store (E-05)
		{"policy_store", "policy/"},       // the configured policy file
		{"evidence_journal", "state/journal/"},
		{"key_material", "state/keys/"},
		{"trust_anchors", "state/tls/"},
		{"server_registry", "state/packages/registry.json"}, // the Local Server Registry (E-14)
		{"vault", "state/vault/"},
	} {
		if has(c.prefix) && !contains(out, c.name) {
			out = append(out, c.name)
		}
	}
	if has("state/trust/") && !contains(out, "trust_anchors") {
		out = append(out, "trust_anchors")
	}
	for name := range optional {
		out = append(out, "optional:"+name)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Write streams an encrypted archive to w and returns its manifest.
func Write(w io.Writer, s Spec) (Manifest, error) {
	rs, err := s.Encryption.recipients()
	if err != nil {
		return Manifest{}, err
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	enc, err := age.Encrypt(w, rs...)
	if err != nil {
		return Manifest{}, err
	}
	bw := bufio.NewWriterSize(enc, 1<<16)
	tw := tar.NewWriter(bw)
	m := Manifest{Format: Format, CreatedAt: s.Now().UTC(), InstallationID: s.InstallationID, Version: s.Version}
	add := func(name, src string) error {
		e, err := addFile(tw, name, src)
		if err != nil {
			return err
		}
		m.Files = append(m.Files, e)
		return nil
	}
	// A just-opened journal segment with no event (after the backup sealed
	// the journal) is left out, so the archive ends at a signed segment.
	emptyOpen, err := audit.EmptyOpenSegment(filepath.Join(s.StateDir, "journal"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return m, fmt.Errorf("journal: %w", err)
	}
	if err := filepath.WalkDir(s.StateDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(s.StateDir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		top := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if excluded[top] || (d.IsDir() && excludedDirs[filepath.ToSlash(rel)]) || strings.Contains(filepath.Base(p), ".tmp-") || strings.HasPrefix(filepath.Base(p), ".health-probe-") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil // directories are implied; links and devices are not archived
		}
		if emptyOpen != "" && filepath.ToSlash(rel) == "journal/"+emptyOpen {
			return nil
		}
		return add("state/"+filepath.ToSlash(rel), p)
	}); err != nil {
		return m, fmt.Errorf("state directory: %w", err)
	}
	if s.ConfigPath != "" {
		if err := add("config/"+filepath.Base(s.ConfigPath), s.ConfigPath); err != nil {
			return m, fmt.Errorf("configuration: %w", err)
		}
	}
	if s.PolicyPath != "" {
		if err := add("policy/"+filepath.Base(s.PolicyPath), s.PolicyPath); err != nil {
			return m, fmt.Errorf("policy: %w", err)
		}
	}
	names := make([]string, 0, len(s.Optional))
	for n := range s.Optional {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		src := s.Optional[n]
		if strings.ContainsAny(n, "/\\") || n == "" || n == "." || n == ".." {
			return m, fmt.Errorf("optional part name %q is invalid", n)
		}
		if err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return err
			}
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return err
			}
			if rel == "." {
				rel = filepath.Base(src)
			}
			return add("optional/"+n+"/"+filepath.ToSlash(rel), p)
		}); err != nil {
			return m, fmt.Errorf("optional part %s: %w", n, err)
		}
	}
	m.Components = components(m.Files, s.Optional)
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(mb)), ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
		return m, err
	}
	if _, err := tw.Write(mb); err != nil {
		return m, err
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	if err := bw.Flush(); err != nil {
		return m, err
	}
	return m, enc.Close()
}

func addFile(tw *tar.Writer, name, src string) (FileEntry, error) {
	f, err := os.Open(src)
	if err != nil {
		return FileEntry{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return FileEntry{}, err
	}
	mode := uint32(st.Mode().Perm())
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(mode), Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}); err != nil {
		return FileEntry{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), f)
	if err != nil {
		return FileEntry{}, err
	}
	if n != st.Size() {
		return FileEntry{}, fmt.Errorf("%s changed size while being archived", src)
	}
	return FileEntry{Path: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: mode}, nil
}

// Result reports a written archive.
type Result struct {
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Size     int64    `json:"size"`
	Manifest Manifest `json:"manifest"`
}

// IndexEntry is one recorded backup in <dir>/index.json.
type IndexEntry struct {
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
	Components []string  `json:"components"`
	Result     string    `json:"result"` // "ok" or the error
}

// Create writes an archive into dir as smcp-backup-<UTC time>.age with its
// .sha256 file and appends the result to dir/index.json. A failed backup
// is recorded too and leaves no archive behind.
func Create(dir string, s Spec) (Result, error) {
	if s.Now == nil {
		s.Now = time.Now
	}
	if _, err := s.Encryption.recipients(); err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, err
	}
	now := s.Now().UTC()
	name := filepath.Join(dir, "smcp-backup-"+now.Format("20060102T150405.000Z")+".age")
	res, err := create(name, s)
	entry := IndexEntry{Path: name, SHA256: res.SHA256, Size: res.Size, CreatedAt: now, Components: res.Manifest.Components, Result: "ok"}
	if err != nil {
		entry.Result = err.Error()
		entry.Path, entry.SHA256, entry.Size = "", "", 0
	}
	if ierr := appendIndex(dir, entry); ierr != nil && err == nil {
		err = ierr
	}
	return res, err
}

func create(name string, s Spec) (Result, error) {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Result{}, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(name)
		}
	}()
	h := sha256.New()
	cw := &countWriter{w: io.MultiWriter(f, h)}
	m, err := Write(cw, s)
	if err != nil {
		return Result{}, err
	}
	if err := f.Sync(); err != nil {
		return Result{}, err
	}
	if err := f.Close(); err != nil {
		return Result{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := os.WriteFile(name+".sha256", []byte(sum+"  "+filepath.Base(name)+"\n"), 0o600); err != nil {
		return Result{}, err
	}
	ok = true
	return Result{Path: name, SHA256: sum, Size: cw.n, Manifest: m}, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// IndexFile is the backup index under the backup directory.
const IndexFile = "index.json"

func appendIndex(dir string, e IndexEntry) error {
	list, err := ReadIndex(dir)
	if err != nil {
		return err
	}
	list = append(list, e)
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, IndexFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, IndexFile))
}

// ReadIndex returns the recorded backups, oldest first.
func ReadIndex(dir string) ([]IndexEntry, error) {
	b, err := os.ReadFile(filepath.Join(dir, IndexFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var list []IndexEntry
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", IndexFile, err)
	}
	return list, nil
}

// FileSHA256 returns the hex SHA-256 of a file.
func FileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyChecksum compares an archive with its .sha256 file. It returns
// false, nil when there is no checksum file.
func VerifyChecksum(archive string) (bool, error) {
	b, err := os.ReadFile(archive + ".sha256")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	want := strings.Fields(string(b))
	if len(want) == 0 {
		return false, errors.New("checksum file is empty")
	}
	got, err := FileSHA256(archive)
	if err != nil {
		return false, err
	}
	if got != want[0] {
		return false, fmt.Errorf("archive checksum mismatch: file %s, recorded %s", got, want[0])
	}
	return true, nil
}

// Extract decrypts an archive into dest (created with mode 0700, must not
// exist or be empty) and verifies every entry against the manifest. Entries
// with unsafe paths, non-regular types, or missing from or extra to the
// manifest fail the extraction.
func Extract(archive, dest string, d Decryption) (Manifest, error) {
	ids, err := d.identities()
	if err != nil {
		return Manifest{}, err
	}
	f, err := os.Open(archive)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	r, err := age.Decrypt(bufio.NewReader(f), ids...)
	if err != nil {
		return Manifest{}, fmt.Errorf("decrypt: %w", err)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return Manifest{}, err
	}
	tr := tar.NewReader(r)
	got := map[string]FileEntry{}
	var m *Manifest
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return Manifest{}, fmt.Errorf("archive entry %q is not a regular file", h.Name)
		}
		if h.Name == "manifest.json" {
			var mm Manifest
			if err := json.NewDecoder(io.LimitReader(tr, 16<<20)).Decode(&mm); err != nil {
				return Manifest{}, fmt.Errorf("manifest: %w", err)
			}
			m = &mm
			continue
		}
		clean := path.Clean(h.Name)
		if clean != h.Name || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." {
			return Manifest{}, fmt.Errorf("archive entry %q has an unsafe path", h.Name)
		}
		target := filepath.Join(dest, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return Manifest{}, err
		}
		// Public files (certificates, public keys) stay world-readable;
		// everything else is owner-only. Nothing is restored writable by
		// others.
		perm := os.FileMode(0o600)
		if h.Mode&0o044 != 0 {
			perm = 0o644
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			return Manifest{}, err
		}
		hs := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, hs), tr) //nolint:gosec // size is checked against the manifest below
		cerr := out.Close()
		if err != nil {
			return Manifest{}, err
		}
		if cerr != nil {
			return Manifest{}, cerr
		}
		got[clean] = FileEntry{Path: clean, Size: n, SHA256: hex.EncodeToString(hs.Sum(nil))}
	}
	if m == nil {
		return Manifest{}, errors.New("archive has no manifest")
	}
	if m.Format != Format {
		return *m, fmt.Errorf("archive format %q is not %q", m.Format, Format)
	}
	for _, e := range m.Files {
		g, ok := got[e.Path]
		if !ok {
			return *m, fmt.Errorf("archive lacks %s listed in the manifest", e.Path)
		}
		if g.SHA256 != e.SHA256 || g.Size != e.Size {
			return *m, fmt.Errorf("%s does not match the manifest checksum", e.Path)
		}
		delete(got, e.Path)
	}
	for p := range got {
		return *m, fmt.Errorf("archive entry %s is not in the manifest", p)
	}
	return *m, nil
}
