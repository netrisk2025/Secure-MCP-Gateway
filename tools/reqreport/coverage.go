package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Coverage is statement coverage overall and per package.
type Coverage struct {
	TotalPct float64      `json:"totalPct"`
	Packages []PackageCov `json:"packages"`
}

// PackageCov is the statement coverage of one package.
type PackageCov struct {
	Name string  `json:"name"`
	Pct  float64 `json:"pct"`
}

type block struct {
	stmts   int
	covered bool
}

// parseCoverProfile reads a Go coverprofile. A block can appear more than
// once when several test binaries were built with -coverpkg; it counts as
// covered when any occurrence has a non-zero count.
func parseCoverProfile(r io.Reader, module string) (*Coverage, error) {
	blocks := map[string]*block{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<22)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			if strings.HasPrefix(line, "mode:") {
				continue
			}
		}
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		// file.go:12.3,14.5 2 1
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("coverprofile: malformed line %q", line)
		}
		stmts, err1 := strconv.Atoi(f[1])
		count, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("coverprofile: malformed line %q", line)
		}
		b := blocks[f[0]]
		if b == nil {
			b = &block{stmts: stmts}
			blocks[f[0]] = b
		}
		if count > 0 {
			b.covered = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	type acc struct{ total, covered int }
	per := map[string]*acc{}
	var all acc
	for key, b := range blocks {
		file, _, _ := strings.Cut(key, ":")
		pkg := shortPackage(path.Dir(file), module)
		a := per[pkg]
		if a == nil {
			a = &acc{}
			per[pkg] = a
		}
		a.total += b.stmts
		all.total += b.stmts
		if b.covered {
			a.covered += b.stmts
			all.covered += b.stmts
		}
	}
	cov := &Coverage{TotalPct: pct(all.covered, all.total), Packages: []PackageCov{}}
	for name, a := range per {
		cov.Packages = append(cov.Packages, PackageCov{Name: name, Pct: pct(a.covered, a.total)})
	}
	sort.Slice(cov.Packages, func(i, j int) bool { return cov.Packages[i].Name < cov.Packages[j].Name })
	return cov, nil
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return round1(100 * float64(n) / float64(d))
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// coverFuncTotal runs `go tool cover -func` on the profile and returns the
// total percentage it reports, which is the figure developers see locally.
func coverFuncTotal(profile string) (float64, error) {
	out, err := exec.Command("go", "tool", "cover", "-func="+profile).Output()
	if err != nil {
		return 0, fmt.Errorf("go tool cover -func: %w", err)
	}
	return parseCoverFuncTotal(string(out))
}

func parseCoverFuncTotal(out string) (float64, error) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "total:" {
			v, err := strconv.ParseFloat(strings.TrimSuffix(f[len(f)-1], "%"), 64)
			if err != nil {
				return 0, fmt.Errorf("go tool cover -func: bad total line %q", line)
			}
			return round1(v), nil
		}
	}
	return 0, fmt.Errorf("go tool cover -func: no total line")
}

// loadCoverage reads the profile; the total comes from `go tool cover -func`
// when it succeeds, otherwise from the profile itself.
func loadCoverage(profile, module string) (*Coverage, error) {
	f, err := os.Open(profile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cov, err := parseCoverProfile(f, module)
	if err != nil {
		return nil, err
	}
	if total, err := coverFuncTotal(profile); err == nil {
		cov.TotalPct = total
	} else {
		fmt.Fprintln(os.Stderr, "reqreport: warning:", err, "(using the total computed from the profile)")
	}
	return cov, nil
}

// shortPackage strips the module path so names read "internal/edge".
func shortPackage(pkg, module string) string {
	if module == "" {
		return pkg
	}
	if pkg == module {
		return "."
	}
	return strings.TrimPrefix(pkg, module+"/")
}

// modulePath reads the module line of go.mod.
func modulePath(gomod string) string {
	b, err := os.ReadFile(gomod)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}
