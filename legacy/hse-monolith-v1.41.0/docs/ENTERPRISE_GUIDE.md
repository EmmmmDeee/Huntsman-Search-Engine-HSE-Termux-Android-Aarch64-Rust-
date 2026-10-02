# See-Know Enterprise Features — Planning Reference (Not Implemented)

> **⚠️ Not implemented — never built.** The three `/enterprise/discord/*`
> endpoints this guide documents are Enterprise-plan-gated and, per
> `docs/SEEKNOW_SETUP.md`'s endpoint reference table, were never built: no
> code in `src/modules/see_know/` calls them. Their 5-credit prices below are
> real (tracked in `ENDPOINT_COSTS`, `src/util/see_know/config.rs`, for
> budgeting purposes and CI-checked against this doc), but the "automatically
> detects enterprise tier" language some earlier versions of this guide used
> describes a dispatch path that does not exist — nothing below can currently
> be exercised against a live scan; `hse doctor` reports no tier-detection
> status, and no `PlanTier`/tier-detection code exists anywhere in `src/`.

## Overview
This guide covers enterprise-only features in the See-Know module, including Discord history export, raw message access, and advanced reporting.

## What the See-Know Enterprise plan advertises

Per the vendor's own plan tiers, an Enterprise subscription adds:
- `/enterprise/discord/history` — historical Discord conversation archive
- `/enterprise/discord/messages` — raw message content export
- `/enterprise/discord/export` — packaged ZIP export with metadata
- Advanced cascade resolution, priority support, a custom SLA, and a higher
  daily credit allowance than the Pro tier

None of this is wired into HSE. If you have an Enterprise-tier SeekNow key
today, HSE will not dispatch these endpoints for you — you would need to
call them yourself outside HSE.

## Credit cost reference (if/when built)

These are the vendor's advertised per-call credit costs, kept here so this
document stays useful as a planning reference; they're checked against
this repo's own `ENDPOINT_COSTS` table by `tests/doc_drift.rs`, so they
won't silently drift from whatever HSE's config says:

```
/search: 1 credit
/search/deep: 1 credit (if fast /search returned empty)
/username/social: 1 credit
/discord/user: 1 credit
/enterprise/discord/history: 5 credits ← enterprise only
/enterprise/discord/messages: 5 credits ← enterprise only
/enterprise/discord/export: 5 credits ← enterprise only
```

Daily credit allocation the vendor advertises by tier: Free 300/day, Pro
1,000/day, Enterprise 5,000/day (contact the vendor for current pricing —
see https://see-know.ru/plans).

## If you want to use these endpoints today

Since HSE doesn't dispatch them, you'd call the See-Know API directly with
your Enterprise key and your own HTTP client, outside HSE. See the vendor's
own documentation for the current request/response shapes — this repo makes
no claim about them since nothing here has been built or tested against
them.

## Notes for whoever implements this

- `SEEKNOW_SETUP.md` documents the real, currently-dispatched endpoints and
  their actual priority/dispatch order — start there to see how a new
  endpoint gets wired into the module.
- `src/util/see_know/enterprise_config.rs` previously carried hardcoded
  `daily_limit`/`per_scan_cap` constants for this tier; they were removed
  because a fixed number is wrong for any operator on a different actual
  plan — any real implementation needs to read the operator's actual limits
  from the API, not hardcode the numbers above.
- No tier-detection code exists (`grep -r PlanTier src/` returns nothing) —
  that would need to be built from scratch, most likely as a live probe
  similar to how `hse doctor`'s existing "SeekNow account" section already
  probes `/credits`.
