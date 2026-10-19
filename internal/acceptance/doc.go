// Package acceptance holds the automated acceptance scenarios AT-01 to
// AT-21 of SRS Appendix M (FR-19.4). The tests build the real smcpd,
// smcpctl and smcp-refserver binaries, bootstrap fresh instances in
// temporary directories and drive them as an operator and a harness would:
// through the CLI, the control API and an MCP client that signs in with
// OAuth. Each test claims its scenario with reqtest.Scenario in the profile
// the Gateway actually reported, and its requirements with reqtest.Partial
// or reqtest.Verifies. AT-07 needs a browser and is claimed by the
// console's Playwright suite; scenarios whose evidence is in other packages
// are claimed there. docs/acceptance.md lists where each scenario runs.
//
// Set SMCP_ACCEPTANCE_PROFILE=enforced on a Linux host with rootless Podman
// to run the same scenarios in the Enforced profile.
package acceptance
