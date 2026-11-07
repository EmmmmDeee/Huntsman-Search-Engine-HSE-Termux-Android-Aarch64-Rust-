# Retained-person birth-history audit

The read-only `huntsman-recon scans people-audit` command walks **every retained saved scan** and emits one newline-delimited JSON object for each recorded person occurrence, including:

- a person-name scan target, even when the scan has no saved results;
- every Person entity in other scans;
- every SpiderFoot `HUMAN_NAME` data element, including those marked false positive.

Each output includes scan ID, time, name, entity UIDs, origin categories, false-positive state, source-attributed POB / DOB claims and conflicts, plus **conditional** historical jurisdiction context when the recorded birthplace is recognisably Dushanbe / Stalinabad / Dyushambe. Source citations embedded in context are background documentation, not proof about that person's birth.

Unknown POB and DOB remain unknown. The audit makes **no nationality, ethnicity, citizenship, family, migration or identity assertions** from a birthplace string. Names are **not** resolved across distinct scan IDs merely because they match. Original scan files, raw claims, timestamps and provenance are never modified; no internet access, API keys, provider requests or runtime LLM are used.

## Android Termux usage

```sh
# Write the results as a private file, outside the repository.
umask 077
huntsman-recon scans people-audit > "$HOME/person-history-audit.jsonl"

# Explicit scan-store location:
huntsman-recon scans people-audit --dir "$HOME/.huntsman/scans"
```

The last JSONL line is a summary. Each unreadable scan produces an explicit `scan_read_error` record, increments `scans_unreadable` and makes the command exit nonzero, without discarding records from other scans.

## Scope and limits

"Every" means **every person occurrence in every retained, readable saved scan**, **not** every person ever looked up on the machine. Direct `people NAME` calls made without saving, past deleted/pruned scans, other installations and remote copies cannot be recovered from the retained scan store. The scan store currently lists at most 4,096 scans; exceeding that cap fails explicitly rather than returning a deceptive partial list. Results are processed one scan at a time to avoid loading the entire collection into phone memory.

This is an **evidence coverage audit**, not automatic independent verification. It does not add missing birthplaces by guessing from names, IP geolocation, languages, surnames or ethnic statistics. The current jurisdiction reference rule applies only to Dushanbe historical names; all other places remain un-enriched pending an independently validated, dated historical gazetteer. No automatically derived context upgrades a source's evidence grade.

Recommended further work after compiling and on-device acceptance: expose bounded server-side pagination in the Web UI, add validated authoritative historical gazetteers with date-effective boundaries for more locations, and ingest previously exported or backed-up scans through explicit, non-destructive import provenance.
