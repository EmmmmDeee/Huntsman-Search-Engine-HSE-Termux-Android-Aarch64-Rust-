- `netblock CIDR` (and `scan -k netblock`, `sf -s`, saved scans and `/api/lookup`) now reads,
  as `ip ADDRESS` does, RIPEstat's RPKI validation state for each origin of the announced prefix
  covering the block, kept on the origin's AS record, and the prefix's routing history: every
  origin AS other than the current ones seen announcing a prefix that overlaps the block (one
  holding it or one inside it). An invalid origin tags the block `rpki_invalid_origin` and other
  origins tag it `prefix_origin_history`, each a lead and never proof of a hijack; a failed read
  is recorded as failed. Both front-ends now build this evidence in one place
  (`routing_context`).
