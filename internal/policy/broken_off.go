//go:build !smcp_broken

package policy

// BrokenBuild is true only in a binary built with the smcp_broken tag: a
// deliberately defective Gateway whose decider ignores rate limits and
// approval obligations. The real-agent suite builds it to show that its
// results turn to fail when enforcement breaks (SRS FR-15.8). Release and
// test builds never set the tag.
const BrokenBuild = false
