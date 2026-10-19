package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/ethan03805/secure-mcp-gateway/internal/reqtest"
)

// testRelease writes a GitHub-release-shaped directory: the archive for
// this platform holding files, the checksum file and its minisign
// signature (prehashed, as minisign -S makes it, with GoReleaser's
// trusted comment). It returns the directory and the public key.
func testRelease(t *testing.T, version string, files map[string][]byte) (dir, pubkey string, priv minisign.PrivateKey) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	archive := fmt.Sprintf("smcp_%s_%s_%s.tar.gz", version, runtime.GOOS, runtime.GOARCH)
	if err := os.WriteFile(filepath.Join(dir, archive), tgzFiles(t, files), 0o644); err != nil {
		t.Fatal(err)
	}
	other := fmt.Sprintf("smcp_%s_plan9_386.tar.gz", version)
	writeFile(t, dir, other, "another platform")
	sumsName := fmt.Sprintf("smcp_%s_checksums.txt", version)
	sums := fmt.Sprintf("%s  %s\n%s  %s\n", sha(t, filepath.Join(dir, archive)), archive, sha(t, filepath.Join(dir, other)), other)
	writeFile(t, dir, sumsName, sums)
	writeFile(t, dir, sumsName+".minisig", string(signRelease(priv, []byte(sums), "smcp "+version+" file:"+sumsName)))
	return dir, pub.String(), priv
}

func signRelease(priv minisign.PrivateKey, msg []byte, comment string) []byte {
	r := minisign.NewReader(bytes.NewReader(msg))
	_, _ = r.Read(make([]byte, len(msg)+1))
	return r.SignWithComments(priv, comment, "signature from test key")
}

func tgzFiles(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(files[n])), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestVerifyReleaseDir(t *testing.T) {
	// FR-13.7 verifies the release as in FR-13.2: the checksum file's
	// minisign signature with the release key and the archive's SHA-256;
	// a failure extracts nothing.
	reqtest.Partial(t, "FR-13.7")
	goos, goarch := runtime.GOOS, runtime.GOARCH
	files := map[string][]byte{"smcpd": []byte("d"), "smcpctl": []byte("c"), "README.md": []byte("r"), "../escape": []byte("x"), "sub/nested": []byte("n")}
	verify := func(dir, pk string) (*verifiedRelease, []os.DirEntry, error) {
		tmp := t.TempDir()
		rel, err := verifyReleaseDir(dir, pk, goos, goarch, tmp)
		ents, _ := os.ReadDir(tmp)
		return rel, ents, err
	}
	refused := func(name, dir, pk, want string) {
		t.Helper()
		_, ents, err := verify(dir, pk)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, want)
		}
		if len(ents) != 0 {
			t.Errorf("%s: extracted files although verification failed", name)
		}
	}

	dir, pk, priv := testRelease(t, "9.9.9", files)
	rel, _, err := verify(dir, pk)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "9.9.9" || rel.Archive != fmt.Sprintf("smcp_9.9.9_%s_%s.tar.gz", goos, goarch) {
		t.Fatalf("release %+v", rel)
	}
	ents, _ := os.ReadDir(rel.Dir)
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != "README.md,smcpctl,smcpd" {
		t.Fatalf("extracted %v (nested and escaping paths must be skipped)", got)
	}
	if fi, _ := os.Stat(filepath.Join(rel.Dir, "smcpd")); fi.Mode().Perm() != 0o755 {
		t.Fatalf("smcpd mode %v", fi.Mode())
	}

	// The release key is the default; a release signed by another key fails.
	refused("default key", dir, releasePublicKey, "does not verify")
	other, _, _ := minisign.GenerateKey(rand.Reader)
	refused("other key", dir, other.String(), "does not verify")
	refused("bad key", dir, "not a key", "release public key")

	sumsName := "smcp_9.9.9_checksums.txt"
	archive := rel.Archive
	cp := func() string {
		d := t.TempDir()
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			_ = os.WriteFile(filepath.Join(d, e.Name()), b, 0o644)
		}
		return d
	}

	d := cp()
	_ = os.Remove(filepath.Join(d, sumsName+".minisig"))
	refused("no signature", d, pk, "no minisign signature")

	d = cp()
	b, _ := os.ReadFile(filepath.Join(d, sumsName))
	_ = os.WriteFile(filepath.Join(d, sumsName), append(b, []byte("0000  extra\n")...), 0o644)
	refused("modified checksum file", d, pk, "does not verify")

	d = cp()
	_ = os.WriteFile(filepath.Join(d, archive), tgzFiles(t, map[string][]byte{"smcpd": []byte("evil"), "smcpctl": []byte("c")}), 0o644)
	refused("modified archive", d, pk, "checksum mismatch")

	d = cp()
	_ = os.Remove(filepath.Join(d, sumsName))
	refused("no checksum file", d, pk, "exactly one")

	d = cp()
	sb, _ := os.ReadFile(filepath.Join(d, sumsName))
	_ = os.WriteFile(filepath.Join(d, sumsName+".minisig"), signRelease(priv, sb, "smcp 9.9.9 file:smcp_1.0.0_checksums.txt"), 0o644)
	refused("trusted comment names another file", d, pk, "trusted comment")

	// A signed release without smcpctl.
	d2, pk2, _ := testRelease(t, "9.9.9", map[string][]byte{"smcpd": []byte("d")})
	refused("missing smcpctl", d2, pk2, "does not contain smcpctl")

	// No archive for this platform.
	if _, err := verifyReleaseDir(dir, pk, "plan9", "arm", t.TempDir()); err == nil || !strings.Contains(err.Error(), "does not list") {
		t.Errorf("other platform: %v", err)
	}
}

func TestReleasePublicKeyMatchesInstallSh(t *testing.T) {
	// smcpctl upgrade and install.sh check releases with the same key, the
	// one SECURITY.md publishes.
	reqtest.Partial(t, "FR-13.7")
	sh, err := os.ReadFile(filepath.Join(repoRoot, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^PUBKEY="([^"]+)"$`).FindSubmatch(sh)
	if m == nil || string(m[1]) != releasePublicKey {
		t.Fatalf("install.sh PUBKEY %q differs from releasePublicKey", m)
	}
	sec, err := os.ReadFile(filepath.Join(repoRoot, "SECURITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sec, []byte(releasePublicKey)) {
		t.Fatal("SECURITY.md does not publish releasePublicKey")
	}
	var pk minisign.PublicKey
	if err := pk.UnmarshalText([]byte(releasePublicKey)); err != nil {
		t.Fatal(err)
	}
}
