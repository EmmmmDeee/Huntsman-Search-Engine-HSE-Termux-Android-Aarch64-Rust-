- A crawl (`scan --recurse`, and a saved scan run with recursion) no longer records a pivot it
  found as the operator's own seed. The e-mail, exposure, username and network lookups each echo
  the selector they were asked back as the operator's seed: tagged `seed`, at confidence 0.99, with
  a seed record that said `operator-supplied … selector`. When the crawl looked up a pivot, that
  echo folded into the entity the pivot was followed from. So a weak lead, such as a handle guessed
  from an e-mail's local part (inferred, at 0.7), left the crawl at 0.99, tagged `seed`, with a
  record saying the operator gave it. Its effective confidence and the correlation rules that read
  it then held the lead as certain, and the entity-reality view labelled its record the operator's
  seed. A pivot's lookup now leaves no echo in the entities the crawl keeps: the record and the tag
  are not kept, the entity keeps the confidence the crawl followed it at, what sources said of it
  is kept, and the echo is no longer counted as an observation. A source that held the pivot higher
  does not raise it, as a pivot is no more likely the subject's than the lead it was followed from
  (an account under a guessed handle exists, which says nothing of whose it is). What the echo
  leads to is followed at no more than that confidence either, so a spelling a source reported of
  the guessed handle is not held at 0.99 one lookup later. The crawl still routes a pivot's lookup
  and records it in the lineage as the lookup returned it, so the pivot is not looked up again by
  its identity key and its lookup still shows in the Discovery Tree. A lookup's seed record now
  says the selector is the one the lookup was asked, not that the operator supplied it. A saved
  scan's report text keeps each lookup's own report as the lookup printed it, so there a pivot's
  lookup still lists its selector at 0.99 tagged `seed`; the scan's entities do not. The operator's
  own seeds keep their records. Scans saved earlier keep the records they were saved with.
