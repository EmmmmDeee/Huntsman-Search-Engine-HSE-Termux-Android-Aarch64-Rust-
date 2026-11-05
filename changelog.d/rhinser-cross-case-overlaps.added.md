- `osint workspace FILE overlaps`, `POST /api/rhinser/overlaps` and a web UI panel list exact
  source URLs that more than one case in a local Rhinser workspace refers to. The route sits behind
  the same token and same-site checks as the other offline OSINT routes. The comparison runs
  offline over the operator's own export, and a URL two cases share is a lead for review, not
  independent corroboration.
