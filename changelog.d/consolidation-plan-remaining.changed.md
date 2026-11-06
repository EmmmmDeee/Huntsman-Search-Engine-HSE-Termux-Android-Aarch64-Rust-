- `docs/CONSOLIDATION_PLAN.md` now holds the open refactor and consolidation list, measured on
  `main` at `094504310`. Since the plan's first baseline, duplicated 10-line windows in
  production code fell from 244 to 178. The list's items:
  - **One authority per rule.** Twenty-nine identical per-source report structs, nineteen
    identical `miss` helpers, five URL-host readers, two DER readers, two checked file openers,
    four copies of one bounded-query rule, and two archived-page summaries.
  - **Two real defects.** The CLI and the Web UI can each lose the other's key save, because only
    an in-process lock guards the keys file. And LTE and NR survey rows accept a 0°, 0° location
    that RF sightings refuse.
  - **Four output changes, declared in advance (B5 to B8).** Each has its guard and acceptance
    test. Items already in `docs/implementation/queue.json` are cross-referenced, not repeated.
