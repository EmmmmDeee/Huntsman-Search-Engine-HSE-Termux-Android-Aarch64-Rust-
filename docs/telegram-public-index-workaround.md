# Huntsman Telegram public-index discovery

**Scope:** Keyless, permission-conscious discovery of *publicly indexed* Telegram links and related public catalogues, through Huntsman's existing `public-osint web` Rust transport. No Telegram login, bot token, MTProto session, private-group enumeration, or access-control bypass. Search-engine results are **unverified leads**, never evidence of account ownership, group membership, or identity.

## Run

From the canonical Huntsman repository with `huntsman-recon` installed:

```sh
# Four default site-filtered search cohorts, 3 built-in engines per cohort.
bash scripts/telegram-public-discovery.sh --output "$HOME/telegram-case-1" example topic

# Eight opt-in cohorts: four default + Telegraph, TelegramChannels and Reddit catalogues.
bash scripts/telegram-public-discovery.sh --expanded --output "$HOME/telegram-case-2" example topic

# Offline verification first; live search is explicitly opt-in.
bash scripts/telegram-termux-acceptance.sh
bash scripts/telegram-termux-acceptance.sh --live example topic
```

Default source filters are `site:t.me/s`, `site:t.me`, `site:tgstat.com`, and `site:telemetr.io`. `--expanded` adds `site:telegra.ph`, `site:telegramchannels.me`, `site:reddit.com/r/TelegramChannels`, and `site:reddit.com/r/TelegramGroups`. An index may ignore the `site:` operator; *neither the domain nor content of returned URLs is independently validated by this wrapper*. Cross-engine overlap is not independent corroboration.

## Resource and data integrity limits

- **Per-cohort timeout:** 65 seconds by default; `HUNTSMAN_TELEGRAM_TIMEOUT_SECS` accepts 1–120 seconds.
- **Whole-run budget:** 240 seconds by default; `HUNTSMAN_TELEGRAM_TOTAL_TIMEOUT_SECS` accepts 1–600 seconds. Unexecuted cohorts are recorded as `not_run_budget_exhausted` with exit 75, not misreported as empty results.
- **Input bound:** 120 UTF-8 bytes, with control characters, quotes and backslashes rejected before network I/O. This preserves the underlying 160-byte Huntsman request ceiling even for the longest expanded site filter.
- **Private outputs:** creates a *new* mode-700 directory, mode-600 files under `umask 077`, and rejects pre-existing case directories. Avoid storing sensitive selectors unless needed and authorised.
- **Raw evidence:** each `*.json` is kept byte-for-byte, with separate `*.stderr`. `manifest.tsv` contains the search cohort, exit status, effective query, filename, response state, byte size, SHA-256 digest and elapsed seconds.
- **Exit semantics:** 0 means at least one underlying web-search cohort reported an answer, **not** that there was a finding. Exit 65 indicates an empty report despite process exit 0; 69 means no cohort answered; 124 indicates an actual cohort timeout; 75 marks skipped cohorts after total budget exhaustion. Individual source failures remain visible even if the wrapper exits 0.
- **Dependencies:** GNU coreutils (`timeout`, `sha256sum`, `wc`) and the canonical Huntsman binary. No new paid API, scraped Telegram session or Rust runtime crate.

Verify one raw report's integrity:

```sh
sha256sum "$HOME/telegram-case-1/telegram_public_channels.json"
# Compare its digest with the same row in manifest.tsv.
```

## Current constraints

This wrapper does not parse URLs into verified Telegram channels, inspect posts, identify account owners, or reconcile channel IDs. A subsequent native Rust ingestion stage should classify canonical Telegram hosts and public message links, reject userinfo/host-spoofing and redirect ambiguity, deduplicate per post/channel, and attach independent source timestamps and source-level outcomes before promoting any claim beyond *candidate*.

For authorised direct Telegram interaction, prefer official API methods and explicit, secure credential storage. The Bot API token is part of its HTTPS URL path: do **not** add it to generic URLs or logs without guaranteed path-based credential redaction. Telegram's global public search may require paid Stars; the zero-cost flow must never automatically authorise charges. Review official API terms and applicable privacy constraints before collecting data.

See https://core.telegram.org/api , https://core.telegram.org/method/channels.searchPosts and https://core.telegram.org/api/terms .

## Verification and release gates

```sh
bash -n scripts/telegram-public-discovery.sh scripts/test-telegram-public-discovery.sh scripts/telegram-termux-acceptance.sh
bash scripts/test-telegram-public-discovery.sh
bash scripts/telegram-termux-acceptance.sh
```

The above are **offline shell tests**; they do not establish that public providers are reachable. Physical Termux acceptance (`--live`), strict Rust workspace gates and GitHub Actions exact-head checks must be run separately before integration. Current draft PR #1845 is not cleared to merge. CI failures at multiple unrelated heads are pre-runner (`runner_id=0`, no executed steps), with exact account cause unresolved; do not bypass branch protection.