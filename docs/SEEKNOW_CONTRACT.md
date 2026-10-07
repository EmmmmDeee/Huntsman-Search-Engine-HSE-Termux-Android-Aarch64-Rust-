# SeekNow public API contract

Observed and re-verified: **2026-10-07**

This file records the public SeekNow contract that Huntsman is allowed to depend
on. It intentionally excludes private UI endpoints, user content, credentials,
and undocumented scraping targets.

## Current service identity

- Canonical live site: `https://see-know.ru`
- Public API base: `https://see-know.ru/api/v1`
- Public API documentation: `https://see-know.ru/api-docs`
- `https://see-know.eu`: DNS resolution failed during the 2026-10-07 check.
- Advertised mirror `https://see-know.vip`: DNS resolution failed during the
  2026-10-07 check.

The sitemap was live and dated the API-docs page 2026-09-29. A broad site crawl
received HTTP 429 at low concurrency, so Huntsman must not use crawl/rate-limit
evasion as a discovery strategy.

## Authentication

The public documentation shows:

```text
Authorization: Bearer seek-YOUR_API_KEY
```

Live unauthenticated requests to `/status`, `/credits`, `/search`, and
`/stealer` returned HTTP 401 with an `invalid_api_key` envelope stating that
the service accepts either `X-API-Key` or Bearer authentication. Huntsman uses
`X-API-Key`, bound to the exact SeekNow origin by the guarded fetch boundary.

## Documented public endpoints

| Method | Path | Cost | Purpose |
| --- | --- | ---: | --- |
| GET | `/status` | free | API status |
| GET | `/credits` | free | API credit state |
| POST | `/search` | 1 credit | general breach/identity search |
| POST | `/stealer` | 2 credits | stealer/deep search |

The current public API documentation does **not** define
`/api/v1/search/deep`. Huntsman's historical `--deep` CLI flag is retained
for compatibility but maps to the documented `/stealer` endpoint.

## Query types

`POST /search` documents:

```text
auto email username phone ip domain name hash
```

`POST /stealer` documents:

```text
auto email username ip domain url machine_id
```

The public playground exposes a `limit` input bounded from 1 through 1000.
Huntsman therefore caps one normalized response at 1000 rows.

## Rate and cost model

The public docs state these per-minute limits:

| Plan | Requests/minute |
| --- | ---: |
| Beginner | 20 |
| Pro | 30 |
| PremiumHQ | 60 |

Earlier rendered documentation in the same current bundle also states daily
allowances of 100, 500, and 5000 respectively. These provider limits are
external policy and can change; Huntsman must still honor provider HTTP 429
responses and observed rate-limit headers.

## Integration invariants

1. `Person` selectors use the documented `name` search type.
2. `Url` and `DeviceId`/machine-id selectors are stealer-only.
3. Phone and name selectors are search-only and must never trigger `/stealer`
   merely because `/search` returned zero rows.
4. Email, username, IP, and domain selectors may escalate from a
   contract-validated fast zero to `/stealer` when request budget permits.
5. A forced endpoint that does not support a selector must fail before transport.
6. Sensitive fields from provider rows are detected and their values discarded.
7. Provider lineage comes from response dataset/source metadata, never from the
   aggregator name alone.
8. No authenticated live-search acceptance claim is valid unless the operator
   has supplied a current `HUNTSMAN_SEEKNOW_KEY`.

## Verification boundary

As of 2026-10-07, the live unauthenticated contract and public documentation are
verified. Authenticated upstream success is **not** verified in Railway because
no `HUNTSMAN_SEEKNOW_KEY` is configured on the current Railway services.
Synthetic transport fixtures exercise request construction, parser behavior,
routing, provenance, redaction, and failure handling without querying any real
person or exposed credential.
