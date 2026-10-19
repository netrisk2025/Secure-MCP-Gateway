package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// stageArtifact copies the executable of an image-less server into
// runtime.shared_dir when Podman runs as runtime.run_as. The executable
// often lives where only the Gateway identity can read it (packaged
// servers are unpacked into the state directory), and Podman, running as
// run_as, must resolve the bind-mount source. The copy is stored by digest
// (<shared_dir>/bin/<hex>/<name>, mode 0755), checked against the digest
// the launch specification records, and the mount is pointed at it; the
// artifact named in the specification and its evidence is unchanged.
func (l *Launcher) stageArtifact(ls *LaunchSpec) error {
	if l.run.runAs == nil || ls.Artifact.Image != "" {
		return nil
	}
	hexDigest, ok := strings.CutPrefix(ls.Artifact.Digest, "sha256:")
	if !ok || len(hexDigest) != 64 || strings.ContainsAny(hexDigest, "./") {
		return fmt.Errorf("server artifact %s has no sha256 digest", ls.Artifact.Command)
	}
	target := ServerBinDir + "/" + filepath.Base(ls.Artifact.Command)
	idx := -1
	for i, m := range ls.Mounts {
		if m.Target == target && m.Source == ls.Artifact.Command {
			idx = i
		}
	}
	if idx < 0 {
		return nil
	}
	dir := filepath.Join(l.o.Runtime.SharedDir, "bin", hexDigest)
	dst := filepath.Join(dir, filepath.Base(ls.Artifact.Command))
	if d, err := FileDigest(dst); err == nil && d == ls.Artifact.Digest {
		ls.Mounts[idx].Source = dst
		return nil
	}
	for _, d := range []string{filepath.Join(l.o.Runtime.SharedDir, "bin"), dir} {
		if err := os.MkdirAll(d, 0o755); err != nil { // #nosec G301 -- run_as and instance UIDs must traverse it
			return fmt.Errorf("stage server artifact: %w", err)
		}
		if err := os.Chmod(d, 0o755); err != nil { // #nosec G302 -- the umask must not narrow it
			return fmt.Errorf("stage server artifact: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".stage-")
	if err != nil {
		return fmt.Errorf("stage server artifact: %w", err)
	}
	defer os.Remove(tmp.Name())
	src, err := os.Open(ls.Artifact.Command)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("stage server artifact: %w", err)
	}
	_, err = io.Copy(tmp, src)
	src.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("stage server artifact: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil { // #nosec G302 -- an executable for other UIDs
		return fmt.Errorf("stage server artifact: %w", err)
	}
	if d, err := FileDigest(tmp.Name()); err != nil || d != ls.Artifact.Digest {
		return errors.Join(fmt.Errorf("stage server artifact: the copy of %s does not match %s", ls.Artifact.Command, ls.Artifact.Digest), err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("stage server artifact: %w", err)
	}
	ls.Mounts[idx].Source = dst
	return nil
}
