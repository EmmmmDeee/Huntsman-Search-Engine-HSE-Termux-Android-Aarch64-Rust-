# Public Nominatim operational contract

The `geocode` command uses OpenStreetMap Foundation's **public** Nominatim geocoder. Its usage policy is authoritative: https://operations.osmfoundation.org/policies/nominatim/ . This is for occasional operator-triggered lookup, not an unrestricted source for automated scanning.

## Enforced within one Huntsman process

- Both forward and reverse queries enter one shared mutex. A new HTTP attempt starts no sooner than **one second after the preceding attempt completed**, including refusals and transport errors; requests do not overlap.
- A bounded in-memory cache retains at most 64 validated, non-truncated HTTP 200 JSON documents no larger than 64 KiB each (the same limit as raw-evidence retention), for at most 24 hours (monotonic age). Repeated identical URLs reuse their originally observed data and keep their original UNIX observation time. HTTP refusals and invalid documents are not cached.
- The existing guarded HTTP egress, identifying `User-Agent`, failure classification and evidence entity normalisation remain unchanged. An open circuit breaker is **not** a rate limiter.
- The cache is deliberately process-local, ephemeral and contains only raw previously successful response documents; it is not a durable evidence ledger.

## Not guaranteed by a process-local gate

The policy's maximum of **one request per second applies across the entire application**, not independently per process, Android handset or user. Multiple Huntsman processes or installations cannot share this in-memory gate. Operators **must not** route multiple clients directly to the OSMF public endpoint when their combined rate could exceed this threshold; use a centrally throttled/cached provider or a self-hosted service instead. An environment-wide, replaceable endpoint/proxy is not yet implemented. This remains tracked in issue #1195.

Do not enable periodic geocoding in continuous scans or conduct bulk/distributed/systematic geocoding against the public endpoint. The provider imposes additional restrictions on periodic scripts, requires caching for bulk cases, and forbids autocomplete and systematic grid queries. Do not submit confidential or personal information. Include OpenStreetMap attribution and respect ODbL as appropriate to the output.

This implementation is a **single-process rate and cache correction**. Passing deterministic fake-transport tests and an Android cross-build does not establish actual handset-runtime operation or compliance for multi-device deployment.
