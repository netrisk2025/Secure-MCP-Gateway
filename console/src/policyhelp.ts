// Help text for every field of the policy document (FR-8.25), keyed by its
// path in internal/policy/policy.schema.json ("[]" stands for a map value
// or a list item). It is part of the console bundle, so help is read from
// the local build and never fetched. console/e2e/help.spec.ts checks that
// every schema field has an entry and that every G-02 form field shows its
// entry. The text follows docs/policy-reference.md.
export const policyHelp: Record<string, string> = {
  revision: "Revision ID of the document: letters, digits, dot, dash or underscore, at most 64 characters. Every published document needs a new ID; a published ID never carries other content.",
  framework_profiles: "Framework Profiles by name. A principal's profile in smcp.toml or G-11 names one; it decides which templates the principal's sessions may use.",
  "framework_profiles[].templates": "Templates that sessions of this profile may use. Each must exist in the document.",
  "framework_profiles[].default_template": "Template used when the harness asks for none. It must be one of the profile's templates.",
  "framework_profiles[].calls_per_minute": "Rate bound for all calls under this profile, at least 1. Empty means no profile bound.",
  "framework_profiles[].servers": "Authority ceiling: the server aliases this profile's sessions may reach through any template. Absent means unrestricted. Edit it in the document (JSON).",
  "framework_profiles[].high_risk": "High-risk tool classes (general-sql, code-execution, cad-scripting, browser-automation) the profile's sessions may be granted. Edit it in the document (JSON).",
  "framework_profiles[].remote_allowed": "Templates of this profile that sessions created through the Remote Access listener may use; each must also be listed in the configuration's remote.templates. Absent means no remote session for this profile. Edit it in the document (JSON).",
  templates: "Session Allow Policy Templates by name. A session runs under exactly one template.",
  "templates[].description": "Free text shown with the template.",
  "templates[].calls_per_minute": "Rate bound for calls under this template. Empty means no template bound.",
  "templates[].calls_per_session": "Quota: calls one session may make under this template over its lifetime. Empty means no quota.",
  "templates[].taint_action": "What a tainted session gets for tools whose side-effect class is not read: approve (an approval obligation, the default) or deny.",
  "templates[].high_risk": "High-risk tool classes this template may grant; the profile must flag them too. Edit it in the document (JSON).",
  "templates[].rules": "Permit and deny rules of the template. An empty list permits nothing.",
  "templates[].rules[].id": "Rule ID, unique within the template. Decisions report it as the considered, applicable and decisive rule.",
  "templates[].rules[].effect": "permit (default) or deny. A deny rule wins over every permit for the same tool and takes no other settings.",
  "templates[].rules[].server": "Server alias the rule applies to, as in [[server]] alias or the enabled package's alias.",
  "templates[].rules[].tools": "Backend tool names, separated by spaces. A deny rule may use * for every tool of the server; a permit rule may not.",
  "templates[].rules[].approval": "Adds an approval obligation: calls are refused with APPROVAL_REQUIRED until a person approves them in G-13 or with smcpctl approvals.",
  "templates[].rules[].calls_per_minute": "Rate bound for calls this rule permits. Empty means no rule bound.",
  "templates[].rules[].calls_per_session": "Quota: calls one session may make through this rule. Empty means no quota.",
  "templates[].rules[].side_effect": "read, write, external or execute. Combined with the verified manifest's class; the more restrictive one applies. Empty uses the manifest's.",
  "templates[].rules[].source_trust": "trusted or untrusted. Combined with the manifest's value; untrusted wins. Empty uses the manifest's.",
  "templates[].rules[].filters": "Optional request and response filters that must run on calls this rule permits. Mandatory filters always run.",
  "templates[].rules[].egress_limits": "Bounds on each outbound operation the server makes through the Egress Broker while serving a call this rule permits. The smallest of these, the manifest's and the [egress] configuration's applies. Edit them in the document (JSON).",
  "templates[].rules[].egress_limits.request_bytes": "Largest request body, or bytes sent through a tunnel, of one egress operation.",
  "templates[].rules[].egress_limits.response_bytes": "Largest response body, or bytes received through a tunnel, of one egress operation.",
  "templates[].rules[].egress_limits.timeout_ms": "Longest duration of one egress operation, in milliseconds (at most 3,600,000).",
  "templates[].rules[].when": "Argument predicates of a permit rule, at most 32; the rule applies only when every one holds. Edit them in the document (JSON).",
  "templates[].rules[].when[].op": "Predicate operator: eq, in, range, path_within, url_in, data_class_in, expiry or approval.",
  "templates[].rules[].when[].arg": "Name of the tool argument the predicate tests (not used by expiry and approval).",
  "templates[].rules[].when[].value": "Value or list the argument is compared with: a value for eq, a list for in, path_within, url_in and data_class_in, \"required\" for approval.",
  "templates[].rules[].when[].min": "range: the smallest number the argument may be.",
  "templates[].rules[].when[].max": "range: the largest number the argument may be.",
  "templates[].rules[].when[].not_before": "expiry: RFC 3339 time from which the rule applies.",
  "templates[].rules[].when[].not_after": "expiry: RFC 3339 time from which the rule no longer applies.",
};

/** The help text of a policy field; throws on a path without help so a new field cannot ship without it. */
export function helpFor(path: string): string {
  const h = policyHelp[path];
  if (!h) throw new Error(`no help for policy field ${path}`);
  return h;
}
