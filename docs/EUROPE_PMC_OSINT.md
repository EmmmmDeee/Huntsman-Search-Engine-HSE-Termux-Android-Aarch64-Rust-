# Europe PMC biomedical OSINT — native Rust

This module extends **Huntsman Search Engine (HSE)** with a public life-sciences
literature index alongside existing GDELT news, FBI notices, public web engines and
the separately proposed Crossref scholarly-record source.

The underlying REST API is provided by EMBL-EBI/Europe PMC:
https://dev.europepmc.org/RestfulWebService

## Use

```sh
huntsman-recon public-osint biomed "CRISPR base editing"
```

The same live collector can be reached through the existing /api/lookup route
with `kind=biomed`, `q=<percent-encoded query>`, and the required Huntsman lookup
header and any configured local authentication. It does not add a new HTTP listener,
persistent service or runtime LLM.

## Execution contract

- **One** GET to `https://www.ebi.ac.uk/europepmc/webservices/rest/search`.
- `format=json&resultType=lite&pageSize=8`, provider-host pacing, no redirects.
- Reuses the shared HTTP transport with a **512 KiB** response cap.
- Query limited to **160 UTF-8 bytes**; refuse controls before trimming.
- Validate echoed query, page size, result type, unsigned hit count, array schema,
  row count, duplicate IDs and URL-path components.
- A response with zero matches is `valid_zero` **only** when `hitCount == 0`,
  the page is empty, and the echoed request matches. Nonzero hit count with an
  empty page is `zero_yield_anomaly`; errors and malformed payloads fail closed.
- Cited articles are **Url** entities. Title, original source ID, DOI, authors'
  printed byline, journal, year, publication type and first publication date are
  metadata on the source receipt. No person, organisation or affiliation identity
  is inferred, and bibliographic co-occurrence is not independent corroboration.
- `hit_count` and `truncated` expose page coverage. No pagination, no automatic
  cross-database identity collapse, no full-text scraping or credentials.

## Source limitations

Europe PMC provides an index, not peer review verification. Publication claims
can be superseded by corrections, retractions or subsequent work. A displayed
author byline is not identity proof, and identical names may refer to distinct
people. An article result does not establish wrongdoing, medical diagnosis,
family relationships or the location of an individual.

The endpoint also supports preprints and grants through other resources, but
this first integration retrieves only the bounded `lite` article search.
Crossref, PubMed, ORCID and other sources may share upstream records. Do not
count duplicate DOIs or mirrored indexes as independent corroboration.

## Verification

Tests in `src/europe_pmc.rs` use the repository's existing synthetic HTTP
transport: positive result, exact validated zero, contradictory count,
invalid/duplicate article paths, missing envelope and query-control refusal.
The REST contract was also inspected against live Europe PMC 200 responses on
2026-11-22. **Live API schema inspection is not a Rust/Android build test.**

As of this patch, GitHub Actions is account billing-locked and cannot run a real
Rust CI job. The change remains isolated for actual formatting, Clippy, test
suite, rootless AArch64 Termux and integrated Web UI verification. Do not merge
or deploy until required gates pass.
