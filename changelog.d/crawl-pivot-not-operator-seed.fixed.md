- A crawl (`scan --recurse`, and a saved scan run with recursion) no longer records a pivot it
  found as the operator's own seed. Every lookup echoes the selector it was asked back as the
  operator's seed: tagged `seed`, at confidence 0.99, with an `operator-supplied … selector`
  record. When the crawl looked up a pivot, that echo folded into the entity the pivot was
  followed from, so a weak lead such as a handle guessed from an e-mail's local part (inferred,
  at 0.7) left the crawl at 0.99, tagged `seed`, carrying a record that says the operator gave it.
  Everything that reads that record then treated the lead as the operator's input: the
  cross-scan filter kept it however weak, the entity-reality role called it the operator's seed,
  and the attack-reporting and trafficking-graph views left it out as a seed. A pivot's lookup
  now leaves no echo in the crawl: the record and tag are not kept, the entity keeps the
  confidence the crawl followed it at, what sources said of it is kept, and the echo is not
  counted as an observation. The operator's own seeds keep their records. Scans saved earlier
  keep the records they were saved with.
