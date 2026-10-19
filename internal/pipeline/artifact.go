package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// LaunchArtifact is the content address of a command-configured server
// (SR-3.6-1): the SHA-256 of the command file and of every launch argument
// that names an existing regular file by absolute path (a script given to
// an interpreter, for example). Signed packages are content-addressed by
// the Library Trust Verifier instead (E-13).
type LaunchArtifact struct {
	// Digest is "sha256:<hex>" over the sorted "<path>\x00<file sha256>\n"
	// lines of Files.
	Digest string `json:"digest"`
	// CommandSHA256 is the hex SHA-256 of the command file.
	CommandSHA256 string `json:"command_sha256"`
	// Files maps each hashed path to its hex SHA-256.
	Files map[string]string `json:"files"`
	// Pinned is set when the operator pinned CommandSHA256 in the
	// configuration (command_sha256) rather than the Gateway recording it.
	Pinned bool `json:"pinned"`
}

// ContentAddress hashes the files a command-configured launch executes or
// hands to its interpreter. The command must be an absolute path to a
// regular file. Arguments that are not absolute paths of regular files
// (flags, directories, missing paths) are not part of the address.
func ContentAddress(command string, args []string) (LaunchArtifact, error) {
	a := LaunchArtifact{Files: map[string]string{}}
	if !filepath.IsAbs(command) {
		return a, fmt.Errorf("%w: command %q must be an absolute path", ErrUnpinnedLaunch, command)
	}
	sum, err := fileDigest(command)
	if err != nil {
		return a, fmt.Errorf("%w: command %s: %w", ErrUnpinnedLaunch, command, err)
	}
	a.CommandSHA256 = sum
	a.Files[command] = sum
	for _, arg := range args {
		if !filepath.IsAbs(arg) {
			continue
		}
		if st, err := os.Stat(arg); err != nil || !st.Mode().IsRegular() {
			continue
		}
		s, err := fileDigest(arg)
		if err != nil {
			return a, fmt.Errorf("%w: argument %s: %w", ErrUnpinnedLaunch, arg, err)
		}
		a.Files[arg] = s
	}
	paths := make([]string, 0, len(a.Files))
	for p := range a.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		fmt.Fprintf(h, "%s\x00%s\n", p, a.Files[p])
	}
	a.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return a, nil
}

// Changed reports the paths whose content differs between a and b (a path
// missing from either counts as changed).
func (a LaunchArtifact) Changed(b LaunchArtifact) []string {
	var out []string
	for p, s := range a.Files {
		if b.Files[p] != s {
			out = append(out, p)
		}
	}
	for p := range b.Files {
		if _, ok := a.Files[p]; !ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the configured launch artifact
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
