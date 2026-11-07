# Retained-person birth-history audit

The read-only `huntsman-recon scans people-audit` command walks **every retained saved scan** and emits one newline-delimited JSON object for each recorded person occurrence, including:

- a person-name scan target, even when the scan has no saved results;
- every Person entity in other scans;
- every SpiderFoot `HUMAN_NAME` data element, including those marked false positive.

Each output includes scan ID, time, name, an occurrence identifier (scan target, numbered Person entity or numbered HUMAN_NAME element), optional entity UID and element ID, the element's false-positive state, source-attributed POB / DOB claims and conflicts, plus **conditional** historical jurisdiction context when the recorded birthplace is recognisably Dushanbe / Stalinabad / Dyushambe. A Person entity and the similarly named search target are separate rows; the output counts occurrences, **not resolved unique humans**. Source citations embedded in context are background documentation, not proof about that person's birth.

Unknown POB and DOB remain unknown. The audit makes **no nationality, ethnicity, citizenship, family, migration or identity assertions** from a birthplace string. Names are **never** joined merely because they match, even within one scan. Birthplace and birth-date claims are linked for historical contextualisation **only when both come from the same saved Evidence record and the record contains exactly one place and one date**. Multiple unpaired places or dates remain separately reported without fabricated place/date combinations; separately sourced facts are never cross-joined. The exact original attribute text and merged source provenance are retained beside any parsed attribute values. A historical label is not proof that the underlying source's assertions are true. The audit opens an existing scan store without creating directories or changing directory permissions; no scan lifecycle recovery or writing occurs. Original scan files, raw claims, timestamps and provenance are never modified; no internet access, API keys, provider requests or runtime LLM are used.

## Android Termux usage

```sh
# Write the results as a private file, outside the repository.
umask 077
huntsman-recon scans people-audit > "$HOME/person-history-audit.jsonl"

# Explicit scan-store location:
huntsman-recon scans people-audit --dir "$HOME/.huntsman/scans"
```

The last JSONL line reconciles **scan-person occurrences** across independently counted search targets, Person entities and HUMAN_NAME elements (including false positives), and records unreadable scans, scans missing results, scans not finished and missing or conflicting birthplace claims. It is a completeness ledger for readable saved records, not a count of unique people or a guarantee that every provider finished. Each unreadable scan produces an explicit `scan_read_error` record, increments `scans_unreadable` and makes the command exit nonzero. If `scan.json` is readable but `results.json` is corrupt, the saved person target is still exported without inventing missing results; original bytes remain unchanged. The completeness flag is **false** whenever a scan is unreadable, unfinished or missing a results file.

## Scope and limits

"Every" means **every person occurrence in every retained, readable saved scan**, **not** every person ever looked up on the machine. Direct `people NAME` calls made without saving, past deleted/pruned scans, other installations and remote copies cannot be recovered from the retained scan store. The scan store currently lists at most 4,096 scans; exceeding that cap fails explicitly rather than returning a deceptive partial list. Results are processed one scan at a time to avoid loading the entire collection into phone memory.

This is an **evidence coverage audit**, not automatic independent verification. A source that omits the birthplace is never replaced with guessed demographic data. Date parsing validates calendar boundaries (including leap years) before choosing a historical period. It does not add missing birthplaces by guessing from names, IP geolocation, languages, surnames or ethnic statistics. The current jurisdiction reference rule applies only to Dushanbe historical names; all other places remain un-enriched pending an independently validated, dated historical gazetteer. No automatically derived context upgrades a source's evidence grade.

Recommended further work after compiling and on-device acceptance: expose bounded server-side pagination in the Web UI, add validated authoritative historical gazetteers with date-effective boundaries for more locations, and ingest previously exported or backed-up scans through explicit, non-destructive import provenance.
