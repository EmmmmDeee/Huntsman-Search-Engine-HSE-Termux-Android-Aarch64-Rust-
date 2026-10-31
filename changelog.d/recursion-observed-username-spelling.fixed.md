- Recursive scans now look up a username pivot by each spelling a source observed it under,
  through the same route rule an operator's selector goes through, instead of by the entity's
  identity key. A username's key is lowercased with its separators stripped (`PG_Smith`,
  `pg-smith` and `pgsmith` share one entity), so a pivot such as `PG_Smith` was looked up as
  `pgsmith`. Where handles are case- or separator-sensitive (Hacker News, GitHub) that is a
  different account, and its findings were then attached to the investigation. A merged username
  now keeps every spelling sources observed it under, with the highest confidence each was
  observed at (`spellings`). Each one that reaches `--expand-floor` is looked up, the entity's
  own spelling first. So a Gravatar profile's `pg_smith` and its verified GitHub account
  `PGSmith` are both looked up: GitHub refuses `pg_smith` as a login. The handle a lookup was
  asked, which every lookup returns as its seed, is the query and not an observation: it adds no
  spelling, raises none, and the handle is not looked up again by its identity key. A username
  that reaches the floor only through a guess, such as one guessed from an e-mail's local part,
  with no observed spelling reaching it, is still looked up by its identity key, the
  separator-free form most platforms accept; one observed only below the floor is not looked up,
  as before. The entity keeps its own `raw_value`.
- A crawl de-duplicates lookups as the planner routes seeds, folding only ASCII case: a
  platform's echo of a handle in another case is not looked up again, while seeds `@pg-smith`
  and `@pg_smith` are both looked up. The lineage, the analysis graph and the saved scan's
  discovery tree resolve an edge recorded under any spelling of one identity to the same entity,
  and what a lookup of a username target found stays under the target.
