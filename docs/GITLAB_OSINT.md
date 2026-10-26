# GitLab public-account intelligence

`gitlab_user` is a keyless, pure Rust OSINT source in the existing `username HANDLE`
collector fan-out. It works through the shared guarded HTTP transport; no GitLab
account, token, scraper, new runtime dependencies or LLM are required.

## Collection

One read-only GET to GitLab.com's documented Users API:

```text
https://gitlab.com/api/v4/users?username=<canonical-handle>&per_page=1
```

The username filter is exact (case-insensitive), not a fuzzy people search.
Only a single matching public user response is admitted. The module stores
GitLab's numeric account ID, declared display name (as a **claim**, not a
separate person identity), account state and canonical profile link.

Two evidence-backed entities are produced: `username` and `url`.
A matching GitLab account does **not** prove that a GitHub, TikTok, Mastodon,
Keybase or any real-world person with the same username controls it.
Human identity inference is deliberately not generated.

## Integration

- `huntsman-recon username HANDLE [--save FILE]`
- `huntsman-recon scan -k username HANDLE`
- Recursive scan username pivots, existing saved evidence and Web UI lookup
- Module selection by `gitlab_user`, and the source execution outcome ledger

Strict response handling distinguishes a documented empty array (`valid_zero`)
from a challenge, HTTP rate limit, authentication failure, invalid JSON, unmatched
username or schema drift. Source records are never accepted on any of those
failure paths. No redirects or credentials. A body bound of 64 KiB protects
rootless Termux's limited memory.

## Regression coverage

Unit tests mock the injected transport for exact account matches, empty results,
foreign/mismatched account returns, invalid selectors, endpoint construction and
no credentials. Full readiness additionally requires the repository's Rust
formatting, Clippy, architecture/runtime catalogues, Rust 1.87/1.99 tests,
Termux AArch64 and phone-sized browser acceptance.

GitLab API specification:
https://docs.gitlab.com/api/users/#list-all-users

A GitLab account lookup is not a search of private projects, email addresses,
direct messages or authenticated account records.
