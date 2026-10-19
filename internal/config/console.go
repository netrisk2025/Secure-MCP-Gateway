package config

// Console holds the control API accounts of the Appendix C roles that no
// other element owns: Operator, Policy Author, Auditor and Researcher
// (FR-8.2). The Administrator is [admin], Approvers are
// [[approvals.account]] and Session Approvers are [[approver]].
type Console struct {
	Accounts []ConsoleAccount `toml:"account" json:"account"`
}

// ConsoleAccount is one account with one role. A person who holds several
// roles has one account per role.
type ConsoleAccount struct {
	Username     string `toml:"username" json:"username"`
	PasswordHash string `toml:"password_hash" json:"password_hash"`
	// Role is operator, policy_author, auditor or researcher.
	Role string `toml:"role" json:"role"`
}
