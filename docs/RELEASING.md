# Releasing huntsman-recon (main-channel pre-releases)

`.github/workflows/release.yml` builds the aarch64 Android/Termux binary on every push to `main` and publishes it as `main-<sha7>`, an immutable **pre-release**. It never creates or edits a stable release. The rolling `latest` pre-release moves only when the repository variable `PROMOTE_RECON_TO_LATEST` is exactly `true`. `tests/release_ci.rs` pins everything below and runs in `ci` on every push and PR.

## Jobs

- **build** (read-only token, no `GH_TOKEN`, no persisted git credentials): runs `cargo build` with `HSE_RELEASE=1` and `HUNTSMAN_HIBP_NO_EMBED=1`. It then requires every `out/hibp_embedded_key.txt` to be empty, strips and stages `dist/`, proves that the binary is `huntsman-recon`, and runs the key scanner on `dist/`. Publishing requires `result: PASS (0 findings)`.
- **publish** is the only job with write or OIDC scopes, and it never runs on `pull_request`. It re-checks the downloaded bytes against the build job's digests and re-runs the key scan from the copy inlined in the workflow, which must be byte-identical to `.github/scripts/scan-for-keys.sh`. Then it reconciles orphan main-channel drafts (a draft `main-<sha7>` with no tag), checks for an existing release, checks that this commit is still the `main` head, attests, publishes, and verifies the result through the API. A build whose commit is no longer the `main` head is still built, scanned and attested, but it is not published: it stays a verified Actions artifact.

## Key scanner (`.github/scripts/scan-for-keys.sh`)

The scanner reports a file and a rule name only, as `FINDING file=<path as walked> resolved=<path that was read> rule=<rule> (value withheld)`. It never prints a matched value.

- **Locale:** it runs under `LC_ALL=C`, so matching is byte-wise. In a UTF-8 locale, `[^...]` does not match an invalid byte such as `\xff`, and a key next to one would be missed.
- **Binaries** go through `strings -a -n 8` **and** `strings -a -e l -n 8`, the second pass covering UTF-16LE. If either pass fails, the scan exits 1.
- **Text files** are scanned as-is and also get a high-entropy check.
- **`hibp-key-hex`:** any maximal hex run of 32 or more characters is a finding if it contains 32 lowercase hex characters in a row and its length is not exactly 40 (git SHA-1) or 64 (sha256). This catches a key packed directly against other hex, for example right after `password`, which ends in `d`. Two exceptions are not keys: all-digit runs (std's decimal formatting tables) and the `00..ff` hex byte table, whole or in part.
  - Known limit: a key fused with exactly 8 or 32 neighbouring hex characters forms a 40- or 64-character run and is not flagged.
  - Uppercase-only hex runs are out of scope, because HIBP keys are lowercase.
- **Symlinks:** the same rule applies in this repo and in HSE-BLE-API.
  - A link whose target (`realpath -e`) is a file or directory **inside** the scanned roots is followed, and its target is scanned.
  - A link that is broken, loops, or resolves **outside** every root exits 2 and is named. Examples: `/`, `/proc/self/environ`, a file or directory elsewhere, a `../..` escape.
  - "Inside" is decided on whole path segments, under `LC_ALL=C`: `target == root`, or `target` starts with `root + "/"`. So `/a/root-evil` is not inside `/a/root`. A root of `/` contains everything.
  - Order matters. Links are first listed **without** following them (`find -P … -type l`) and each one is resolved. Only after every link passes does the followed walk (`find -L`) run. So a link to `/` is refused at once, rather than walking the whole filesystem.
  - A directory link back into its own ancestor makes `find -L` report a filesystem loop, which exits 2.
  - After the walk, every file's resolved path is checked again. Files are de-duplicated by resolved path, so a folder reached through N links is scanned once, and one token gives one finding. A file is reported under its own path when the walk also reached it directly.
  - Every read (`cat`, `strings`, the entropy check) goes through the **resolved** path. That path is resolved again and re-checked right before the read. So a link swapped between the pre-check and the walk is still never read outside the roots: the scan exits 2 instead.
  - A dangling link that only appears during the walk is listed by `find -L … -type l`, and it exits 2 as well.
  - Paths are passed NUL-separated throughout (`realpath -z`, `read -d ''`, `mapfile -d ''`) and never go through a command substitution, so a trailing newline in a name survives.
  - **A scan path given as a symlink** is resolved first, and its target becomes the root. A broken or looping one exits 2.
  - A relative scan path that starts with `-` is rewritten to `./-…` before any `find` call, both the `-P` pre-check and the `-L` walk, so `find` never parses it as an option. Without this, a root named `-L`, `-H` or `-P` would switch `find`'s link mode and make it walk `.` instead. Absolute roots are left as they are.
  - This link handling matches HSE-BLE-API #57 (`980a02e`). One difference: a missing tool, `realpath` included, exits 1 here, which keeps this scanner's existing exit-code contract.
  - fifos, sockets and devices exit 2.
  - `realpath` is a required tool: if it is missing, the scan fails closed.
- **File list:** the scanner refuses to scan, with exit 2, when it cannot trust the list. That covers these cases:
  - `find` or `sort` fails
  - the sorted list is not a permutation of what `find` returned (an entry dropped, added, or swapped for a duplicate of another)
  - there are no files at all

  The scan loop runs over the checked array. It never re-reads `sort` through a pipe or a process substitution.
- **Exit status:**
  - 0: clean
  - 1: a finding, a missing tool or path, or an unreadable file
  - 2: an untrusted file list

## Publish refusals

Every refusal in the publish job has its own exit code and an `::error::[refuse:<id>]` marker. `tests/release_ci.rs` runs the extracted steps against a fake `gh` and checks both.

| Step | Exit | Marker | Meaning |
| --- | --- | --- | --- |
| Check for an existing tag | 11 | `tag-elsewhere` | The tag exists at another commit, or as an annotated tag. |
| | 12 | `tag-without-release` | The tag exists at this commit, but there is no published release. |
| | 13 | `not-prerelease` | The existing release is not a pre-release. |
| | 14 | `asset-incomplete` | An asset is missing, duplicated or has no sha256 digest. |
| | 15 | `ref-lookup-failed` | The tag lookup failed with something other than HTTP 404. Only a 404 means "no tag". |
| Require a build provenance attestation | 21 | `no-attestation-id` | A new release got no attestation id. |
| | 22 | `no-asset-digest` | The existing release's binary has no digest. |
| | 23 | `attestation-lookup-failed` | Listing attestations failed with something other than HTTP 404. |
| | 24 | `unattested-release` | The existing release has no build provenance attestation. |
| | 25 | `no-existing-check` | The existing-release check did not run. |

## Attestation is required

`actions/attest-build-provenance` runs without `continue-on-error`, using the publish job's existing `id-token: write` and `attestations: write` permissions. If it fails, nothing is published, and the run fails, including for a superseded build that would only have remained an Actions artifact. A re-run against a release that already exists never re-attests or replaces it. Instead, it requires an attestation for the published binary's digest.

To re-publish an incomplete or unattested release, delete the pre-release **and its tag**, then re-run:

```
gh release delete main-<sha7> --cleanup-tag
```

Deleting only the release, whether in the UI or with `gh release delete` without `--cleanup-tag`, leaves the tag behind. The re-run then stops with `tag-without-release`.

Every step that writes this commit's `main-<sha7>` release, its tag or an attestation is gated on `steps.existing.outputs.exists == 'false'`. Two other writes exist, and the tests pin both: the orphan-draft reconciliation deletes only a draft `main-<sha7>` release whose tag is absent, and the opt-in `latest` move (behind `PROMOTE_RECON_TO_LATEST`) writes only `latest`.

## Termux installer (`.github/scripts/install-termux.sh`)

The installer checks sha256 before installing and stages the binary in a private directory next to its destination. It then re-checks the staged copy, runs the recon binary offline (`check`, then `verify var/ledger.json`), and renames it into place with `mv -fT`. If the destination is a directory, `mv -fT` refuses, instead of moving the binary into that directory and reporting success.
