- The OSINT app blueprint (`blueprint`, `/api/blueprint`, `docs/OSINT_APK_BLUEPRINT.docx`) gains
  two categories: Web archives (Sharchive, mapped to `wayback_cdx`, `common_crawl` and
  `archived_page` through `domain`) and Blockchain (Mempal, mapped to `blockchain` through
  `crypto`), each Partial with its gap and acceptance criterion stated.
- `domain --help` now says the lookup reads the Wayback CDX and Common Crawl indexes and the
  contacts archived pages published.
