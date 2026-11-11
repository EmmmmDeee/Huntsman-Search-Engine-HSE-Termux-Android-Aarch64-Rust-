# HUNTSMAN Intelligence Compendium

## Functionality

The Comprehensive Multi-Source Open-Source Intelligence Compendium is a
**derived, read-only export** from one **existing saved scan**. It does not
issue network requests, execute a new scan, alter evidence, add proprietary
runtime services, or invoke an LLM. It is implemented in pure Rust and shares
the existing scan store, API security boundary, CLI and Web UI.

### Interfaces

- CLI: huntsman-recon scans compendium SCAN_ID -o compendium.txt
- API: GET /api/scans/SCAN_ID/compendium
- Web UI: open a saved scan → Export → Intelligence Compendium TXT

The API returns text/plain; charset=utf-8 with a deterministic filename.
A missing or unreadable scan fails; POST is not supported.

### Content

Twenty stable headings are included, from executive assessment and subject
identification through source reliability, provenance, raw evidence,
intelligence gaps and the final assessment. Under the raw-evidence heading,
the exporter embeds one **complete, machine-readable JSON object** between
these delimiters:

    BEGIN_FULL_SAVED_EVIDENCE_JSON
    {"scan_record":...,"scan_results":...,"scan_log":[...]}
    END_FULL_SAVED_EVIDENCE_JSON

This is a faithful JSON serialization of the stored record structures, **not
a byte-for-byte copy of remote provider HTTP responses**. All saved entity
evidence, full saved report text, elements (including false positives),
source outcomes, correlations, discovery lineage, termination reason and
execution log are represented by the same stored structures as before. A
SHA-256 hash identifies the exact JSON bytes embedded in section 18.

The original binary data of an external source that was **never stored**,
and information about providers never consulted, cannot be recreated.
A saved scan with no evidence does not become evidence of absence.

### Evidence interpretation

Source coverage is explicitly **UNKNOWN BEYOND RECORDED SOURCES**. The
compendium does not automatically mark findings as VERIFIED, claim two
sources are independent, establish a person's identity, or categorise
source modules as having investigated every section. Those analyses require
their own evidence-based gates.

The following evidence classifications are documented, **not assigned
without proof**: SEED → CANDIDATE → OBSERVED → CORROBORATED → VERIFIED;
exceptions REJECTED / CONFLICTED / STALE.

### Size, security and privacy

The finished TXT document is bounded to 8 MiB, with a fail-closed error
rather than truncation. Input results are admitted through the existing
bounded scan-store reader; the log is read from the existing saved log.
The snapshot is non-atomic: avoid active scans for forensic exports.
If the saved data is too large, use unchanged individual raw endpoints
or the existing source evidence export.

This export is **unredacted saved evidence** and may contain personal or
sensitive data. It uses the same existing API authorisation, CSRF/same-origin
and local-server controls as other saved-scan exports. Handle downloaded
files according to the applicable lawful purpose and storage policy.

### Acceptance tests

- Unit: 20 headings; deterministic output; JSON round-trip of all stored
  fields and full log; SHA-256 checksum consistency; refusal at size limit;
  cross-scan ID rejection; source-content heading injection resistance.
- Integration: route returns a real stored scan and log; GET is repeatable;
  POST returns 405 without changing evidence.
- Web UI: existing Download mechanism obtains the new route.
- Preserve legacy Spiderfoot CSV/TSV/XLSX/JSON/GEXF/HTML export formats.

**Verification caveat:** The code is implemented on a separate draft PR;
it must pass actual Rust compilation, repository tests and physical
Termux/Web UI acceptance before merging. If GitHub Actions fails before
steps start, that is not a passing or failing application test.
