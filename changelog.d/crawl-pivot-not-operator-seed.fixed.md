- A crawl (`scan --recurse`, and a saved scan run with recursion) no longer records a pivot it
  found as the operator's own seed. Every lookup echoes the selector it was asked back as the
  operator's seed: tagged `seed`, at confidence 0.99, with an `operator-supplied … selector`
  record. When the crawl looked up a pivot, that echo folded into the entity the pivot was
  followed from. So a weak lead, such as a handle guessed from an e-mail's local part (inferred,
  at 0.7), left the crawl at 0.99, tagged `seed`, with a record saying the operator gave it. Its
  effective confidence and the correlation rules that read it then held the lead as certain, and
  the entity-reality view labelled its record the operator's seed. A pivot's lookup now leaves no
  echo in the crawl: the record and the tag are not kept, the entity keeps the confidence the
  crawl followed it at, what sources said of it is kept, and the echo is no longer counted as an
  observation. The operator's own seeds keep their records. Scans saved earlier keep the records
  they were saved with.
