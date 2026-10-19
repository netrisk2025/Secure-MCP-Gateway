package config

// Approvals configures the Approval Service (E-07). Every key is optional;
// the approval package applies the Appendix A defaults (CP-17 lifetime
// 5 min, CP-45 keep-alive 10 s) to absent keys. The hold bound itself is
// limits.approval_hold (CP-45).
type Approvals struct {
	// Lifetime is how long an approval stays usable after it is requested
	// (CP-17, at most 5 minutes).
	Lifetime Duration `toml:"lifetime" json:"lifetime"`
	// KeepAlive is the interval of progress keep-alives on a held call
	// (CP-45).
	KeepAlive Duration `toml:"keepalive" json:"keepalive"`
	// Notify selects the desktop notifier (X-14): "auto" (the platform
	// notifier when one is installed), "off", "osascript",
	// "terminal-notifier", "notify-send" or "command" (NotifyCommand).
	Notify string `toml:"notify" json:"notify"`
	// NotifyCommand is run with the notification title and body as its two
	// arguments when Notify is "command".
	NotifyCommand string `toml:"notify_command" json:"notify_command"`
	// ConsoleURL is the base of approval deep links
	// (<console_url>/approvals/<id>); default the control API URL.
	ConsoleURL string `toml:"console_url" json:"console_url"`
	// Accounts hold the Approver role (Appendix C): they may decide
	// tool-call approvals and nothing else. Session Approver accounts
	// ([[approver]]) cannot decide tool-call approvals.
	Accounts []ApproverAccount `toml:"account" json:"account"`
}

// ApproverAccount is an account with the Approver role.
type ApproverAccount struct {
	Username     string `toml:"username" json:"username"`
	PasswordHash string `toml:"password_hash" json:"password_hash"`
}
