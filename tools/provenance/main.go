// Command provenance writes the provenance files that go into every
// release archive (SRS FR-12.8, with the SBOM of scripts/release-sbom.sh
// and the build recipe and lockfiles that .goreleaser.yaml copies):
//
//   - PROVENANCE.md: the release version, the source commit and its date,
//     the Go toolchain, the CI run that built it, and the SHA-256 of each
//     build recipe and lockfile in the archive. The digests of the archives
//     themselves are in the release's signed checksum file.
//
//   - THIRD_PARTY_NOTICES.txt: the license files of every Go module linked
//     into the release binaries on linux and darwin, of the Go standard
//     library, and of the npm packages bundled into the console.
//
//     go run ./tools/provenance -version 1.1.0 -out build/provenance
//
// With -require-npm (the release workflow), a bundled npm package whose
// license file is not in console/node_modules is an error; without it the
// notice names the package and its license from package-lock.json.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// releaseCommands are the packages of the release binaries (.goreleaser.yaml).
var releaseCommands = []string{"./cmd/smcpd", "./cmd/smcpctl", "./cmd/smcp-refserver", "./cmd/smcp-session", "./cmd/smcp-stdio", "./cmd/smcp-connect", "./cmd/smcp-workload"}

// RecipeFiles are the build recipe and lockfiles copied into each archive,
// relative to the repository root.
var RecipeFiles = []string{".goreleaser.yaml", "scripts/release-sbom.sh", "go.mod", "go.sum", "console/package-lock.json"}

// licenseNames are the file name prefixes taken for license files.
var licenseNames = []string{"LICENSE", "LICENCE", "COPYING", "NOTICE", "UNLICENSE", "PATENTS"}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "provenance:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("provenance", flag.ContinueOnError)
	version := fs.String("version", "dev", "release version")
	out := fs.String("out", "build/provenance", "output directory")
	root := fs.String("root", ".", "repository root")
	requireNPM := fs.Bool("require-npm", false, "fail when a bundled npm package's license file is missing from console/node_modules")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	mods, err := linkedModules(*root)
	if err != nil {
		return err
	}
	pkgs, err := consolePackages(filepath.Join(*root, "console", "package-lock.json"))
	if err != nil {
		return err
	}
	notices, err := renderNotices(mods, pkgs, filepath.Join(*root, "console", "node_modules"), *requireNPM)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "THIRD_PARTY_NOTICES.txt"), notices, 0o644); err != nil {
		return err
	}
	prov, err := renderProvenance(*root, *version, mods)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, "PROVENANCE.md"), prov, 0o644)
}

// Module is a Go module linked into a release binary.
type Module struct {
	Path, Version, Dir string
}

// linkedModules lists the modules of the release binaries' dependency
// graphs for linux and darwin, without the main module.
func linkedModules(root string) ([]Module, error) {
	seen := map[string]Module{}
	for _, goos := range []string{"linux", "darwin"} {
		args := append([]string{"list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}"}, releaseCommands...)
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		b, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go list (GOOS=%s): %w: %s", goos, err, stderr.String())
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			f := strings.Split(sc.Text(), "\t")
			if len(f) != 3 || f[0] == "" {
				continue
			}
			if f[2] == "" {
				return nil, fmt.Errorf("module %s %s is not in the module cache (run go mod download)", f[0], f[1])
			}
			seen[f[0]+"@"+f[1]] = Module{Path: f[0], Version: f[1], Dir: f[2]}
		}
	}
	out := make([]Module, 0, len(seen))
	for _, m := range seen {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// NPMPackage is a production package of the console's lockfile.
type NPMPackage struct {
	Name, Version, License, Path string
}

func consolePackages(lock string) ([]NPMPackage, error) {
	b, err := os.ReadFile(lock)
	if err != nil {
		return nil, err
	}
	var l struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			License string `json:"license"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", lock, err)
	}
	var out []NPMPackage
	for path, p := range l.Packages {
		if path == "" || p.Dev || !strings.HasPrefix(path, "node_modules/") {
			continue
		}
		name := p.Name
		if name == "" {
			name = path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		}
		out = append(out, NPMPackage{Name: name, Version: p.Version, License: p.License, Path: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// licenseFiles returns the license files directly in dir, sorted.
func licenseFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		up := strings.ToUpper(e.Name())
		for _, n := range licenseNames {
			if strings.HasPrefix(up, n) {
				out = append(out, filepath.Join(dir, e.Name()))
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func appendFiles(b *bytes.Buffer, files []string) error {
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "--- %s\n\n%s\n", filepath.Base(f), bytes.TrimRight(body, "\n"))
		b.WriteString("\n")
	}
	return nil
}

const rule = "================================================================================\n"

func renderNotices(mods []Module, pkgs []NPMPackage, nodeModules string, requireNPM bool) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("Third-party notices for the Secure MCP Gateway release binaries.\n\n")
	b.WriteString("The Gateway itself is licensed under Apache-2.0 (LICENSE). The binaries\n")
	b.WriteString("include the Go modules, the Go standard library and the console npm\n")
	b.WriteString("packages below; their license files follow, unchanged.\n\n")
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return nil, fmt.Errorf("go env GOROOT: %w", err)
	}
	goroot := strings.TrimSpace(string(out))
	b.WriteString(rule)
	fmt.Fprintf(&b, "Go standard library %s\n\n", goVersion())
	if err := appendFiles(&b, []string{filepath.Join(goroot, "LICENSE")}); err != nil {
		return nil, err
	}
	for _, m := range mods {
		files, err := licenseFiles(m.Dir)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("module %s %s has no license file in %s", m.Path, m.Version, m.Dir)
		}
		b.WriteString(rule)
		fmt.Fprintf(&b, "Go module %s %s\n\n", m.Path, m.Version)
		if err := appendFiles(&b, files); err != nil {
			return nil, err
		}
	}
	for _, p := range pkgs {
		b.WriteString(rule)
		fmt.Fprintf(&b, "npm package %s %s (%s)\n\n", p.Name, p.Version, p.License)
		files, err := licenseFiles(filepath.Join(filepath.Dir(nodeModules), p.Path))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if len(files) == 0 {
			if requireNPM {
				return nil, fmt.Errorf("npm package %s %s: no license file under %s (run npm ci in console/)", p.Name, p.Version, p.Path)
			}
			fmt.Fprintf(&b, "License %s according to console/package-lock.json; the license file was not available when this file was written.\n\n", p.License)
			continue
		}
		if err := appendFiles(&b, files); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func goVersion() string {
	if out, err := exec.Command("go", "env", "GOVERSION").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.Version()
}

func git(root string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func fileSHA256(p string) (string, error) {
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

func renderProvenance(root, version string, mods []Module) ([]byte, error) {
	var b bytes.Buffer
	commit := git(root, "rev-parse", "HEAD")
	fmt.Fprintf(&b, "# Provenance of Secure MCP Gateway %s\n\n", version)
	b.WriteString("| Item | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Version | %s |\n", version)
	fmt.Fprintf(&b, "| Source repository | https://github.com/ethan03805/Secure-MCP-Gateway |\n")
	fmt.Fprintf(&b, "| Source commit | `%s` |\n", commit)
	fmt.Fprintf(&b, "| Commit date | %s |\n", git(root, "show", "-s", "--format=%cI", "HEAD"))
	fmt.Fprintf(&b, "| Go toolchain | %s |\n", goVersion())
	if run := os.Getenv("GITHUB_RUN_ID"); run != "" {
		fmt.Fprintf(&b, "| Build run | %s/%s/actions/runs/%s |\n", os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), run)
	} else {
		b.WriteString("| Build run | local build |\n")
	}
	b.WriteString("| Archive digests | SHA-256 in the release's checksum file, signed with the release minisign key (SECURITY.md) and a Sigstore bundle |\n")
	b.WriteString("| SBOM | sbom.spdx.json (SPDX 2.3) in this archive; a per-archive SPDX SBOM is published beside each archive |\n")
	b.WriteString("| License notices | LICENSE (the Gateway, Apache-2.0) and THIRD_PARTY_NOTICES.txt |\n")
	fmt.Fprintf(&b, "| Linked Go modules | %d (listed in THIRD_PARTY_NOTICES.txt and the SBOM) |\n\n", len(mods))
	b.WriteString("Every binary also records the commit in its build information (`go version -m <binary>`, `vcs.revision`).\n\n")
	b.WriteString("## Build recipe and lockfiles in this archive\n\n| File | SHA-256 |\n|---|---|\n")
	for _, f := range RecipeFiles {
		d, err := fileSHA256(filepath.Join(root, f))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", f, d)
	}
	b.WriteString("\nTo rebuild: check out the commit above and run GoReleaser with `.goreleaser.yaml` (the release workflow is `.github/workflows/release.yml` at that commit); `go.sum` and `console/package-lock.json` pin every dependency.\n")
	return b.Bytes(), nil
}
