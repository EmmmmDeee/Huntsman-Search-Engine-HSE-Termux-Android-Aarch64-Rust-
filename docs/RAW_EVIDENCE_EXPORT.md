# Saved-scan raw evidence export

The scan **Summary → Uncertainty register → Save full TXT** control downloads a UTF-8, fenced plain-text evidence dump. Each named section contains the complete JSON representation returned by the current saved-scan API endpoints:

- `SCAN_METADATA`: scan status and attached derived summaries
- `SOURCE_EXECUTIONS`: recorded source outcomes, with available timestamps and details
- `UNCERTAINTY_REGISTER`: unchanged saved-scan uncertainty register
- `DATA_ELEMENTS`: every element returned by the scan elements endpoint, not just the first 200 UI rows
- `CORRELATIONS`: every correlation returned by the scan correlations endpoint
- `RELATIONSHIP_GRAPH`: graph nodes and edges from the scan graph endpoint

Each section is framed by `[START_NAME]` and `[END_NAME]`. JSON is not shortened, filtered, coalesced or paraphrased. The download is a **snapshot of recorded evidence** and explicitly says `COVERAGE: UNKNOWN_BEYOND_RECORDED_SOURCES`. Multiple endpoint reads are not transactional, so the dump declares `CONSISTENCY: NON_ATOMIC_ENDPOINT_SNAPSHOT`; prefer exporting a completed scan. A transport error aborts the export instead of silently omitting an unavailable section.

The browser builds a Blob from text fragments to avoid one extra giant concatenated intermediate string. It nevertheless needs memory for the fetched arrays and output; very large scans can exceed device memory, and the absence of a published size limit is not a performance guarantee. For low-memory workflows use the existing source JSON endpoints individually or a future server-streamed export.

**Verification:** the mobile browser acceptance test downloads the TXT file and parses each named JSON section, comparing metadata, uncertainty, elements, correlations and graph against the saved-scan API response. No new runtime dependencies, API keys or external provider requests are introduced.
