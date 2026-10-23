# Nominatim geocoding: endpoint and public-service contract

Huntsman's existing `geocode` command and the Rust `nominatim::{forward,reverse}`
API issue only one forward or reverse search per call. This deliberately does not
add bulk, periodic, autocomplete, grid-reverse, or address-harvesting features.

## Operator-selected service

The default remains `https://nominatim.openstreetmap.org`. Set
`HUNTSMAN_NOMINATIM_BASE_URL=https://geocode.example.org` to use an alternative,
operator-managed Nominatim-compatible HTTPS service without rebuilding Huntsman.

The environment variable is an **origin only**, not a URL path. Scheme must
be HTTPS, with a qualified DNS hostname and optional valid TCP port. Userinfo,
query strings, fragments, paths and loopback hostnames are rejected rather
than accepted as credentials or SSRF shortcuts. DNS resolution and connection
remain subject to the existing guarded HTTP egress policy. The caller's
transport must not use an unrestricted egress policy for untrusted endpoints.
Changes to the environment are normally made before launching/restarting the
process; no runtime-LLM or API key is required.

The exact configured endpoint, including the origin, is part of the
in-memory response cache key. A response from one endpoint is not reused
as if it came from another. The cache is bounded to 64 complete responses,
each <=64 KiB, and a 24-hour monotonic TTL. No disk cache is created.

## Public service limits

[OSMF Nominatim usage policy](https://operations.osmfoundation.org/policies/nominatim/)
requires an **absolute maximum of one request per second for the whole
application (aggregated across users and instances)**, an identifiable User-Agent
or Referer, visible attribution and caching; see the live policy for
additional restrictions. Huntsman sends its app-version User-Agent and keeps
OpenStreetMap attribution and ODbL in entity evidence.

The process-global mutex serializes transport sends and imposes a full
one-second delay **after** each finished attempt. This satisfies the
one-process spacing invariant, including concurrent queries; the circuit
breaker separately handles provider failures. This mutex **does not
coordinate separate processes, containers, devices or installations**. If
Huntsman is operated in more than one instance, configure a centrally
rate-limited, independently operated Nominatim-compatible endpoint. Do not
route many clients to the public OSMF service assuming their per-process
mutexes provide an aggregate guarantee. Do not put personal/confidential
information into public geocoding queries.

Long-running periodic or bulk requests are additionally restricted by
the policy and are outside this interactive geocode integration.
The public service can change usage terms without notice.

## Verification boundaries

Pure URL construction and endpoint validation use no network. Unit tests
cover invalid origins, invalid coordinates and queries, cache isolation,
explicit attribution, concurrency, and one-second spacing. Locked Rust
1.87/1.99 and Android AArch64 CI remain required. Passing CI cannot prove
multi-process aggregate policy compliance or physical handset acceptance.
