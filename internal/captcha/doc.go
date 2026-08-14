// Copyright 2026 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
