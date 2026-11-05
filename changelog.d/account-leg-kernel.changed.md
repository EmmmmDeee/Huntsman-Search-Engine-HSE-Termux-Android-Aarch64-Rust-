- Eight username legs now share one kernel, `src/account_leg.rs`: Lobsters, Chess.com, Lichess,
  Codeberg, DEV, Codewars, Hugging Face and Hacker News. Each leg used to repeat the same fetch
  and the same checks. No output changes.
  - **What the kernel does.** It reads each account document in one order: a clean zero, then
    the whole document, then drift. Each leg states its exact messages, handle rule, identity rule
    and how its site reports a missing account.
  - **What each leg keeps.** Its own URL, request, document type and entities.
  - **What proves it.** A new snapshot, `tests/fixtures/account_leg_snapshot.tsv`, records how
    each leg ended in eleven scenarios before the move. Those are: found, shouted handle,
    another account, empty, `null`, not JSON, 404, 500, no response, refused, and invalid
    handle. Each row holds the outcome's kind, HTTP status, reason and every entity. All 88 rows
    are unchanged on the kernel, so the outcome messages, which the legs' own tests never
    pinned, are held too.
