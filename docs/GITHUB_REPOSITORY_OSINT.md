# Public GitHub repository OSINT

Huntsman provides an independent, keyless GitHub repository-footprint collector as part of `username HANDLE`, `scan -k username`, saved scans, the HTTP scan API and web UI. Choose `github_repos` in the module selector to run only this source. The existing `github_user` account-profile collector remains independent.

## Method

1. Canonicalise the username and reject path-shaped or invalid GitHub logins before contacting the network.
2. Make one guarded, no-redirect GitHub API GET request to `/users/{login}/repos?type=owner&sort=updated&per_page=30`.
3. Accept only public rows whose owner login, full name and repository ID are internally consistent. Do not follow URLs taken from the response.
4. Extract canonical repository URLs and bounded metadata: stable GitHub identifiers, fork/archival status, programming language, repository description, licence identifier, branch, topics, creation/update/push timestamps and public counters.
5. Save source-attributed evidence as URL entities in the shared graph, provenance and scan ledger. Distinguish observed GitHub account ownership from the natural person's identity.

The same optional `HUNTSMAN_GITHUB_TOKEN` is shared with the GitHub profile collector, using its existing exact API-origin lock. No new credentials or runtime dependencies are required.

## Boundaries

- One recent page is **not exhaustive**. No conclusions are drawn from absent repositories beyond the response actually observed.
- A GitHub repository's homepage is **self-declared and unverified**. It does not prove domain ownership, affiliation or control.
- Stars, forks, issues, topics and timestamps are mutable metadata, not vulnerability findings or identity verification.
- A fork proves neither authorship nor development of the upstream code.
- The adapter reads repository metadata only. It does not enumerate secrets, download code, scan vulnerabilities or use third-party backends.
- Rate-limit, schema-drift, missing-account and transport errors receive distinct source outcomes. No result is never silently presented as verified absence.
- The guarded transport enforces shared public-egress restrictions, timeouts and response-byte limits. The code does not add storage beyond the existing scan ledger.

## Verification

`cargo test --locked --lib github_repos`, `cargo test --locked --lib username_cli`, `cargo test --locked --test runtime_reachability`, and the complete `cargo run --locked -p xtask -- gate full` exercise the adapter and its integration. Actual GitHub-hosted CI results must be checked against the PR head before merging.

## Extensions

A future, separate `repository OWNER/REPO` lookup could analyse the public repository's security policy, default-branch protection signals, advisory disclosures, releases, and public provenance with an explicit collection consent/scope. These are not part of this implementation.
