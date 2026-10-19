package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"aead.dev/minisign"

	"github.com/ethan03805/secure-mcp-gateway/internal/backup"
)

// releasePublicKey is the minisign release key (key ID 064FAC0C64ACCED0),
// the same key install.sh embeds and SECURITY.md publishes. A test keeps
// the three in step.
const releasePublicKey = "RWTQzqxkDKxPBk0ZPk07i/mcrUVaevLmrm8zRkQLqGrs14RwtUhG30Dq"

// maxReleaseFile bounds one extracted file of a release archive.
const maxReleaseFile = 512 << 20

// verifiedRelease is a release directory that passed the FR-13.2 checks.
type verifiedRelease struct {
	Version string // from the checksum file name, e.g. 1.0.0-rc.1
	Archive string // the archive for this platform
	Dir     string // where its files were extracted
}

// verifyReleaseDir checks a downloaded GitHub release the way install.sh
// does (FR-13.2, required by FR-13.7): the minisign signature of
// smcp_<version>_checksums.txt with pubkey, the signed trusted comment
// naming that file, and the SHA-256 of smcp_<version>_<os>_<arch>.tar.gz
// against the verified checksum file. Only then is the archive extracted,
// into a new directory under tmp. smcpd and smcpctl must be in it.
func verifyReleaseDir(dir, pubkey, goos, goarch, tmp string) (*verifiedRelease, error) {
	var pk minisign.PublicKey
	if err := pk.UnmarshalText([]byte(strings.TrimSpace(pubkey))); err != nil {
		return nil, fmt.Errorf("release public key: %w", err)
	}
	sums, err := filepath.Glob(filepath.Join(dir, "smcp_*_checksums.txt"))
	if err != nil {
		return nil, err
	}
	if len(sums) != 1 {
		return nil, fmt.Errorf("%s must hold exactly one smcp_<version>_checksums.txt (found %d)", dir, len(sums))
	}
	sumsName := filepath.Base(sums[0])
	version := strings.TrimSuffix(strings.TrimPrefix(sumsName, "smcp_"), "_checksums.txt")
	sumsBody, err := os.ReadFile(sums[0])
	if err != nil {
		return nil, err
	}
	sigBody, err := os.ReadFile(sums[0] + ".minisig")
	if err != nil {
		return nil, fmt.Errorf("no minisign signature for %s: %w", sumsName, err)
	}
	if !minisign.Verify(pk, sumsBody, sigBody) {
		return nil, fmt.Errorf("the minisign signature of %s does not verify with the release key", sumsName)
	}
	var sig minisign.Signature
	if err := sig.UnmarshalText(sigBody); err != nil {
		return nil, err
	}
	if !strings.Contains(sig.TrustedComment, "file:"+sumsName) {
		return nil, fmt.Errorf("the signed trusted comment of %s.minisig does not name %s", sumsName, sumsName)
	}

	archive := fmt.Sprintf("smcp_%s_%s_%s.tar.gz", version, goos, goarch)
	want := ""
	sc := bufio.NewScanner(strings.NewReader(string(sumsBody)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == archive {
			want = f[0]
		}
	}
	if want == "" {
		return nil, fmt.Errorf("%s does not list %s", sumsName, archive)
	}
	got, err := backup.FileSHA256(filepath.Join(dir, archive))
	if err != nil {
		return nil, err
	}
	if got != want {
		return nil, fmt.Errorf("%s: checksum mismatch (expected %s, got %s)", archive, want, got)
	}

	out, err := os.MkdirTemp(tmp, "smcp-release-")
	if err != nil {
		return nil, err
	}
	if err := extractRelease(filepath.Join(dir, archive), out); err != nil {
		_ = os.RemoveAll(out)
		return nil, fmt.Errorf("extract %s: %w", archive, err)
	}
	for _, need := range []string{"smcpd", "smcpctl"} {
		if fi, err := os.Stat(filepath.Join(out, need)); err != nil || !fi.Mode().IsRegular() {
			_ = os.RemoveAll(out)
			return nil, fmt.Errorf("%s does not contain %s", archive, need)
		}
	}
	return &verifiedRelease{Version: version, Archive: archive, Dir: out}, nil
}

// extractRelease writes the regular files at the top level of a tar.gz
// release archive into dir. Directories, links and nested paths are
// skipped; the release archives have none.
func extractRelease(path, dir string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag != tar.TypeReg || name == "" || name != filepath.Base(name) || name == "." || name == ".." {
			continue
		}
		if h.Size > maxReleaseFile {
			return fmt.Errorf("%s is larger than %d bytes", name, maxReleaseFile)
		}
		mode := os.FileMode(0o644)
		if h.Mode&0o111 != 0 {
			mode = 0o755
		}
		w, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, cerr := io.Copy(w, io.LimitReader(tr, maxReleaseFile))
		if err := w.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return cerr
		}
	}
}

// hostPlatform is the GOOS and GOARCH of release archives for this host.
func hostPlatform() (string, string) { return runtime.GOOS, runtime.GOARCH }
