// Package captcha implements the browser-facing part of CrowdSec captcha
// remediation decisions.
//
// A Service is immutable after construction and safe for concurrent use. Its
// Handle method owns captcha challenge and verification responses, but leaves
// the final remediation policy to its caller through Outcome:
//
//   - OutcomeUnavailable means captcha was not configured. The caller should
//     retain the legacy remediation (normally a ban).
//   - OutcomeChallenge means the service wrote a challenge.
//   - OutcomeSolved means the service accepted a proof and wrote a safe
//     redirect.
//   - OutcomeBypass means a valid, signed passed-cookie matched the request.
//   - OutcomeFallback means captcha could not fail safely on its own (for
//     example, the verification provider was unavailable). The caller should
//     apply its fail-closed remediation.
//
// Handle never forwards a captcha submission. On successful verification it
// responds with 303 See Other, so the module's verification POST is not
// replayed. New challenges are only rendered for GET and HEAD; other original
// methods return OutcomeFallback because their semantics cannot be preserved
// safely. Callers that run body-consuming middleware before remediation can
// use IsSubmission to route marked submissions to Handle first.
package captcha
