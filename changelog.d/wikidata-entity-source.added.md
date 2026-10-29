- `wikidata QUERY` (also reachable in the module catalogue) is a new keyless source: it resolves a
  Q-number or free text to a Wikidata item through the public search and REST APIs, keeps the item
  as a `Person` or `Organisation` candidate with every statement Wikidata holds preserved as
  evidence, and seeds the rest of the engine with pivots -- the official website as a `Domain`, a
  coordinate location as `Coordinates` the geocoder can reverse, and external identifiers (GitHub,
  X, VIAF, ORCID, IMDb and more) as `Url` and `Username` entities. A knowledge-base record is a
  candidate to review, never a confirmed real-world identity, and every record says so.
