//go:build smcp_broken

package policy

// BrokenBuild: see broken_off.go. This file is compiled only with
// -tags smcp_broken, for the FR-15.8 broken-build check.
const BrokenBuild = true
