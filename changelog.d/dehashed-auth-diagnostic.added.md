- Add a manually dispatched, main-branch-only, read-only DeHashed v2 response probe. The genuine HUNTSMAN binary builds without secrets; an existing GitHub repository secret can be supplied only to the probe step. By default no paid search or personal-target data is requested; a separate explicitly opted-in real-domain test may spend one credit. The free-probe wrapper emits only a fixed classification, not raw response data or credential contents.
- Offline regression checks cover valid-looking, rejected, absent, unavailable, malformed and duplicate DeHashed probe rows, and enforce the workflow's no-push/no-PR trigger, read-only permissions and main-ref boundary.
- Isolate the diagnostic from ambient process credentials as well as HOME files. The existing `credential-status --probe` checks all configured providers, so inherited `HUNTSMAN_*` slots and `HIBP_API_KEY` otherwise trigger unrelated provider probes. A new regression first failed on the old wrapper, then passed after the minimal Bash fix; the selected DeHashed key is never placed in a command-line argument.
- Fail closed when a DeHashed status reports `state=configured` and `probe=valid` but its key slot is `unset`, missing or duplicated. New synthetic regressions reproduced the earlier false-positive success and now pass after correcting the parser.
- Correct stale DeHashed documentation: November 2026 authenticated live tests fixed domain-query syntax, but neither their commit logs nor the credit-free `search-password` response prove that a currently accessible GitHub secret works for paid searches. The existing probe's `results_found` schema check is represented as `valid_response`, not independently verified authentication.

- Add an explicit one-credit real-company acceptance command and opt-in
  `workflow_dispatch` input using `telstra.com.au` (real public-domain
  target). It invokes the unchanged Rust DeHashed client with one
  `security-research` exact-match search of one record, suppresses all
  raw breach/provider output, and reports only structural API success
  and aggregate result count. An offline fake-binary contract tests
  successful and empty responses, invalid/mismatched output, missing keys,
  provider failures and `pipefail` handling. No authenticated live
  execution has yet occurred on PR #1811 because GitHub-hosted runners
  have failed before executing steps and an accessible current key is unavailable.
- Preserve real Rust CLI exit codes when DeHashed fails without returning
  stdout; the old `awk` parser error masked key/entitlement and upstream
  errors. Reject stray record fields in a zero-result response. Add offline
  regressions for empty-output failures and inconsistent entries. The manual
  paid-search branch now runs independently of the free probe, avoiding a
  false-negative gate; only one branch runs in a manual invocation.
