# Keyless retrieval — execution note 2026-10-02

Purpose: record what was actually executed after the Seek-Know request and the autonomous directive. Not a client.

## Objective preserved

Autonomous search and retrieval with no API key.

## Rejected path (unchanged)

Seek-Know.ru does not resolve to a keyless search API. Matching product is SeekNow (see-know.ru / see-know.eu): paid breach, stealer, Discord, phone, and IntelX lookups. Upstream cited by wrappers is https://see-know.ru/api/v1 and still expects an account or bearer. No scrape, no cookie replay, no row store.

Classification: NOT APPLICABLE. Evidence level: primary product pages plus third-party API notes. Does not show a hidden keyless endpoint.

## Executed substitute

One JSON search each, no fan-out, query "SearXNG documentation", format=json, timeout 20s, UA huntsman-investigate/1.0.

| Host | HTTP | Body | Result |
| --- | --- | --- | --- |
| https://paulgo.io/search | 429 | Too Many Requests | limiter |
| https://searxng.site/search | 403 | Forbidden HTML | json disabled or blocked |
| https://priv.au/search | 429 | Too Many Requests | limiter |

Earlier /config probes (2026-09-29) on these three hosts returned 200 JSON. Configuration reachability is not search reachability.

## Classification

Public SearXNG JSON search from this egress: UNVERIFIED. Observed blocker is 403/429, not a missing key.

Self-hosted SearXNG with format=json enabled remains the only path that would not depend on a volunteer limiter. Not executed. Termux cannot host the Python SearXNG stack under the current huntsman v1 offline contract without a new spec.

## Stop reason

VERIFIED INFEASIBILITY of keyless SeekNow retrieval.
HARD EXTERNAL BLOCKER on public-instance JSON from this host after three single attempts.
Further instance racing has non-positive expected value (loads volunteer hosts, trips the same limiter class).
