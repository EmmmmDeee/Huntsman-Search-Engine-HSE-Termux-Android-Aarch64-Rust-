- `wikidata QUERY` (also reachable in the module catalogue) is a new keyless source: it resolves a
  Q-number or free text to a Wikidata item through the public search and REST APIs, keeps the item
  as a `Person` candidate when it is a human, an `Organisation` candidate only on a known
  organisation type (otherwise `Other`, never defaulted to an organisation), with every statement
  Wikidata holds preserved as evidence, and seeds the rest of the engine with pivots -- a 200 that
  is not the requested item document is schema drift, never a fabricated entity; the official
  website as a `Domain`, a
  coordinate location as `Coordinates` the geocoder can reverse, and external identifiers (GitHub,
  X, VIAF, ORCID, IMDb and more) as `Url` and `Username` entities. A knowledge-base record is a
  candidate to review, never a confirmed real-world identity, and every record says so.
