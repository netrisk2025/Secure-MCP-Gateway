// Command sbomcheck checks the license fields of SPDX JSON SBOMs against
// SRS FR-12.1: every component of the Gateway release carries an
// OSI-approved license or public-domain status.
//
// For each package of each SBOM (the document root, which describes the
// scanned archive or directory rather than a component, is skipped), the
// license expression is licenseConcluded, or licenseDeclared when the
// concluded value is NOASSERTION, NONE or empty. The expression is
// accepted when it evaluates to true with every OSI-approved or
// public-domain SPDX identifier true and every other identifier false (AND
// needs both sides, OR either, a WITH exception keeps the value of its
// license). A package without any license value is refused.
//
// Identifiers that are not licenses of the component, or license-less
// packages whose license was established by reading their files, are
// accepted only through a reviewed entry in the review file
// (packaging/sbom-review.json): the package name, the identifier (or
// "license" for a package without a license value) and the reason. Each
// review applies to that package only, so a new component or a new
// unrecognized license file fails the check until someone reviews it.
//
//	go run ./tools/sbomcheck -review packaging/sbom-review.json build/dist/*.sbom.json sbom.spdx.json
//
// The exit status is 1 when any package is refused and 2 when an input
// cannot be read.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// osiApproved lists SPDX identifiers of OSI-approved licenses
// (https://opensource.org/licenses, SPDX license list 3.29), and
// publicDomain the identifiers of public-domain dedications.
var osiApproved = set(
	"0BSD", "AFL-3.0", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-1.1", "Apache-2.0", "APSL-2.0",
	"Artistic-2.0", "BlueOak-1.0.0", "BSD-1-Clause", "BSD-2-Clause", "BSD-2-Clause-Patent", "BSD-3-Clause", "BSL-1.0",
	"CDDL-1.0", "CECILL-2.1", "ECL-2.0", "EFL-2.0", "EPL-1.0", "EPL-2.0", "EUPL-1.1", "EUPL-1.2", "GPL-2.0",
	"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "ISC", "LGPL-2.1",
	"LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "LPL-1.02", "MIT", "MIT-0",
	"MPL-1.1", "MPL-2.0", "MS-PL", "MS-RL", "MulanPSL-2.0", "NCSA", "OFL-1.1", "OSL-3.0", "PostgreSQL", "Python-2.0",
	"UPL-1.0", "Unicode-3.0", "Unicode-DFS-2016", "Unlicense", "W3C", "Zlib", "ZPL-2.0", "ZPL-2.1",
)

var publicDomain = set("CC0-1.0", "LicenseRef-Public-Domain")

func set(ids ...string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[strings.ToLower(id)] = true
	}
	return m
}

// Review is one reviewed exception.
type Review struct {
	Package string `json:"package"`
	// Identifier is the refused identifier the review accepts for this
	// package, or "license" for a package with no license value.
	Identifier string `json:"identifier"`
	// License is the license established by the review, for the report.
	License string `json:"license"`
	Reason  string `json:"reason"`
}

type reviewFile struct {
	Reviews []Review `json:"reviews"`
}

type spdxPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
}

type spdxDoc struct {
	SPDXVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`
}

// Finding is the result for one package of one SBOM.
type Finding struct {
	File, Package, Version, Expression string
	// Refused lists identifiers that are neither OSI-approved, public
	// domain nor reviewed for this package ("license" when there is no
	// license value at all).
	Refused []string
	// Reviewed lists the reviews that were needed to accept the package.
	Reviewed []Review
}

func (f Finding) OK() bool { return len(f.Refused) == 0 }

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbomcheck:", err)
	}
	os.Exit(code)
}

func run(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("sbomcheck", flag.ContinueOnError)
	reviewPath := fs.String("review", "packaging/sbom-review.json", "reviewed exceptions")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() == 0 {
		return 2, errors.New("no SBOM given")
	}
	reviews, err := loadReviews(*reviewPath)
	if err != nil {
		return 2, err
	}
	refused := 0
	for _, p := range fs.Args() {
		findings, err := checkFile(p, reviews)
		if err != nil {
			return 2, err
		}
		n := 0
		printed := map[string]bool{}
		for _, f := range findings {
			if !f.OK() {
				refused++
				fmt.Fprintf(out, "REFUSED %s: %s %s: %q (%s)\n", f.File, f.Package, f.Version, f.Expression, strings.Join(f.Refused, ", "))
				continue
			}
			n++
			for _, r := range f.Reviewed {
				// A package appears once per binary that links it.
				line := fmt.Sprintf("reviewed %s: %s %s: %s accepted as %s (%s)", f.File, f.Package, f.Version, r.Identifier, r.License, r.Reason)
				if !printed[line] {
					printed[line] = true
					fmt.Fprintln(out, line)
				}
			}
		}
		fmt.Fprintf(out, "%s: %d packages accepted, %d refused\n", p, n, len(findings)-n)
	}
	if refused > 0 {
		return 1, fmt.Errorf("%d packages without an OSI-approved or public-domain license", refused)
	}
	return 0, nil
}

func loadReviews(p string) ([]Review, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var rf reviewFile
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	for i, r := range rf.Reviews {
		if r.Package == "" || r.Identifier == "" || r.License == "" || r.Reason == "" {
			return nil, fmt.Errorf("%s: review %d lacks package, identifier, license or reason", p, i)
		}
		if !acceptedID(r.License) && !exprAccepted(r.License, nil) {
			return nil, fmt.Errorf("%s: review %d establishes %q, which is not OSI-approved or public domain", p, i, r.License)
		}
	}
	return rf.Reviews, nil
}

func checkFile(p string, reviews []Review) ([]Finding, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var doc spdxDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		return nil, fmt.Errorf("%s: not an SPDX JSON document", p)
	}
	var out []Finding
	for _, pkg := range doc.Packages {
		if strings.HasPrefix(pkg.SPDXID, "SPDXRef-DocumentRoot") {
			continue
		}
		out = append(out, checkPackage(p, pkg, reviews))
	}
	return out, nil
}

func noValue(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || s == "NOASSERTION" || s == "NONE"
}

func checkPackage(file string, pkg spdxPackage, reviews []Review) Finding {
	f := Finding{File: file, Package: pkg.Name, Version: pkg.VersionInfo}
	expr := pkg.LicenseConcluded
	if noValue(expr) {
		expr = pkg.LicenseDeclared
	}
	reviewFor := func(id string) *Review {
		for i := range reviews {
			if reviews[i].Package == pkg.Name && strings.EqualFold(reviews[i].Identifier, id) {
				return &reviews[i]
			}
		}
		return nil
	}
	if noValue(expr) {
		f.Expression = "NOASSERTION"
		if r := reviewFor("license"); r != nil {
			f.Reviewed = append(f.Reviewed, *r)
		} else {
			f.Refused = []string{"license"}
		}
		return f
	}
	f.Expression = expr
	reviewed := map[string]bool{}
	for _, id := range identifiers(expr) {
		if acceptedID(id) {
			continue
		}
		if r := reviewFor(id); r != nil {
			reviewed[strings.ToLower(id)] = true
			f.Reviewed = append(f.Reviewed, *r)
		}
	}
	if !exprAccepted(expr, reviewed) {
		for _, id := range identifiers(expr) {
			if !acceptedID(id) && !reviewed[strings.ToLower(id)] {
				f.Refused = append(f.Refused, id)
			}
		}
		if len(f.Refused) == 0 {
			f.Refused = []string{"expression " + expr}
		}
	}
	return f
}

func acceptedID(id string) bool {
	id = strings.ToLower(strings.TrimSuffix(id, "+"))
	return osiApproved[id] || publicDomain[id]
}

// tokens splits an SPDX license expression into identifiers, operators
// and parentheses.
func tokens(expr string) []string {
	expr = strings.ReplaceAll(strings.ReplaceAll(expr, "(", " ( "), ")", " ) ")
	return strings.Fields(expr)
}

func identifiers(expr string) []string {
	var ids []string
	seen := map[string]bool{}
	afterWith := false
	for _, t := range tokens(expr) {
		switch strings.ToUpper(t) {
		case "AND", "OR", "(", ")":
			afterWith = false
			continue
		case "WITH":
			afterWith = true
			continue
		}
		if afterWith { // a license exception, not a license
			afterWith = false
			continue
		}
		if !seen[t] {
			seen[t] = true
			ids = append(ids, t)
		}
	}
	sort.Strings(ids)
	return ids
}

// exprAccepted evaluates expr with accepted identifiers (OSI, public
// domain, or reviewed for the package) as true. A malformed expression is
// refused.
func exprAccepted(expr string, reviewed map[string]bool) bool {
	p := &parser{toks: tokens(expr), ok: func(id string) bool {
		return acceptedID(id) || reviewed[strings.ToLower(id)]
	}}
	v, err := p.or()
	if err != nil || p.pos != len(p.toks) {
		return false
	}
	return v
}

// parser is a recursive-descent parser for SPDX expressions: OR binds
// looser than AND, AND looser than WITH.
type parser struct {
	toks []string
	pos  int
	ok   func(string) bool
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return strings.ToUpper(p.toks[p.pos])
	}
	return ""
}

func (p *parser) or() (bool, error) {
	v, err := p.and()
	if err != nil {
		return false, err
	}
	for p.peek() == "OR" {
		p.pos++
		w, err := p.and()
		if err != nil {
			return false, err
		}
		v = v || w
	}
	return v, nil
}

func (p *parser) and() (bool, error) {
	v, err := p.atom()
	if err != nil {
		return false, err
	}
	for p.peek() == "AND" {
		p.pos++
		w, err := p.atom()
		if err != nil {
			return false, err
		}
		v = v && w
	}
	return v, nil
}

func (p *parser) atom() (bool, error) {
	switch t := p.peek(); t {
	case "":
		return false, errors.New("unexpected end")
	case "(":
		p.pos++
		v, err := p.or()
		if err != nil {
			return false, err
		}
		if p.peek() != ")" {
			return false, errors.New("missing )")
		}
		p.pos++
		return v, nil
	case ")", "AND", "OR", "WITH":
		return false, fmt.Errorf("unexpected %s", t)
	}
	id := p.toks[p.pos]
	p.pos++
	if p.peek() == "WITH" {
		p.pos++
		if p.peek() == "" || p.peek() == "(" || p.peek() == ")" {
			return false, errors.New("WITH without an exception")
		}
		p.pos++
	}
	return p.ok(id), nil
}
