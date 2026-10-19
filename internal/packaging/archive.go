package packaging

import (
	"archive/tar"
	"compress/gzip"
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
)

// Bounds on unpacked archives.
const (
	maxArchiveFiles = 200000
	maxArchiveBytes = 4 << 30
)

// walkTree lists the regular files and directories under dir in sorted
// order with slash-separated relative paths. Symbolic links and special
// files are refused, so the tree cannot point outside itself.
func walkTree(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files and directories are allowed in an artifact tree", filepath.ToSlash(rel))
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

// TreeDigest is the SHA-256 over a sorted listing of a directory tree:
// each directory by path, each file by executable bit, size, content
// digest and path. It changes when any file is added, removed, altered or
// made executable (SR-3-2).
func TreeDigest(dir string) (string, error) {
	paths, err := walkTree(dir)
	if err != nil {
		return "", err
	}
	h := newHash()
	for _, rel := range paths {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		st, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if st.IsDir() {
			fmt.Fprintf(h, "D %s\n", rel)
			continue
		}
		sum, size, err := FileSHA256(p)
		if err != nil {
			return "", err
		}
		x := "-"
		if st.Mode()&0o111 != 0 {
			x = "x"
		}
		fmt.Fprintf(h, "F %s %d %s %s\n", x, size, sum, rel)
	}
	return h.hex(), nil
}

// TarGzDir writes a deterministic gzip-compressed tar of dir to w: sorted
// entries, zero timestamps and owners, modes normalized to 0755 or 0644.
func TarGzDir(dir string, w io.Writer) error {
	paths, err := walkTree(dir)
	if err != nil {
		return err
	}
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	gz.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(gz)
	for _, rel := range paths {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: rel, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
		switch {
		case st.IsDir():
			hdr.Typeflag, hdr.Name, hdr.Mode = tar.TypeDir, rel+"/", 0o755
		default:
			hdr.Typeflag, hdr.Size, hdr.Mode = tar.TypeReg, st.Size(), 0o644
			if st.Mode()&0o111 != 0 {
				hdr.Mode = 0o755
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, f)
			f.Close()
			if err != nil {
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// cleanArchivePath validates one archive entry name.
func cleanArchivePath(name, strip string) (string, bool, error) {
	n := strings.TrimPrefix(name, "./")
	if strip != "" {
		if n == strings.TrimSuffix(strip, "/") || n == strip {
			return "", false, nil
		}
		if !strings.HasPrefix(n, strip) {
			return "", false, fmt.Errorf("entry %q is outside %s", name, strip)
		}
		n = strings.TrimPrefix(n, strip)
	}
	n = strings.TrimSuffix(n, "/")
	if n == "" || n == "." {
		return "", false, nil
	}
	if strings.HasPrefix(n, "/") || !fs.ValidPath(n) || path.Clean(n) != n {
		return "", false, fmt.Errorf("entry %q is not a relative path inside the archive", name)
	}
	return n, true, nil
}

// ExtractTarGz unpacks a gzip-compressed tar into dest, which must not
// exist. Entries are stripped of the prefix strip (for example "package/"
// of an npm tarball). Only regular files and directories are accepted; any
// path that would leave dest, any link and any special file is refused.
// Files are written read-only (0444, or 0555 when executable).
func ExtractTarGz(archive, dest, strip string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := os.Mkdir(dest, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	var files int
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader || hdr.Typeflag == tar.TypeXHeader {
			continue
		}
		rel, ok, err := cleanArchivePath(hdr.Name, strip)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			files++
			total += hdr.Size
			if files > maxArchiveFiles || total > maxArchiveBytes {
				return errors.New("archive exceeds the unpacking bounds")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o444)
			if hdr.Mode&0o111 != 0 {
				mode = 0o555
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, hdr.Size)); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
			if err := os.Chmod(target, mode); err != nil {
				return err
			}
		default:
			return fmt.Errorf("entry %q: links and special files are not allowed", hdr.Name)
		}
	}
}

// CopyFile copies src to dst (created exclusively) with mode.
func CopyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

// MakeWritable restores owner write permission under dir so it can be
// removed (unpacked trees are read-only).
func MakeWritable(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			if info, e := d.Info(); e == nil {
				_ = os.Chmod(p, info.Mode().Perm()|0o200) //nolint:gosec // only trees this process unpacked under its own state or temporary directory
			}
		}
		return nil
	})
}
