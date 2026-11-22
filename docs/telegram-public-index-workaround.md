# Huntsman: keyless Telegram public-index fallback

Scope: bounded discovery of search-engine-indexed **public** Telegram URLs and references using the existing `huntsman-recon public-osint web` command. Does not access Telegram directly, private chats, membership lists, or any third-party Telegram bot. All hits are leads only.

Prerequisite: install the canonical Huntsman binary and ensure `huntsman-recon` is on `PATH`.

Run:

```bash
bash telegram-public-discovery.sh --output "$HOME/telegram-public-case" channel topic
```

Omit `--output` to create a private timestamped directory. Four search variants are sent sequentially to Huntsman's existing Bing/Brave/Mojeek backend. Each response is preserved as a raw JSON file next to its stderr output; `manifest.tsv` captures per-variant exit codes. A search exit 0 means a source answered, not that a person, account, or claim was verified.

- **Execution budget:** coreutils `timeout` is required; each cohort is capped at 65 seconds (configure `HUNTSMAN_TELEGRAM_TIMEOUT_SECS=1..120`). Exit code 124 marks a timed-out cohort.
- **Integrity:** exit 0 with empty stdout is classified as 65 (data error); upstream failures remain in the manifest. The original raw results are not rewritten.
- **Privacy:** output directories are new-only, mode 700; files are private under `umask 077`. Do not include sensitive selectors unless you intend to store them on the handset.
- **Interpretation:** search engines can ignore `site:` terms or show third-party pages. These raw index results are **not host-verified Telegram evidence**, and repeated indexes are not independent corroboration.

Test offline:

```bash
bash -n telegram-public-discovery.sh test-telegram-public-discovery.sh
bash test-telegram-public-discovery.sh
```

Verification limits: tests use a mock binary, not live provider calls. Full Huntsman cargo tests, Termux acceptance, and PR CI are not verified. The GitHub draft PR must not merge until all required gates pass.

Official constraints: https://core.telegram.org/api/terms and https://telegram.org/tos/bot-developers .