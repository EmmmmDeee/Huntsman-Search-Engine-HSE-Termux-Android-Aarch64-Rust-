- Flagging a scan's element as a false positive flags every element found from it, as
  Spiderfoot's `resultsetfp` does, so Browse with false positives hidden, exports, the graph and a
  re-run of the correlations drop the whole branch a false positive led to instead of keeping its
  ports, hosts and vulnerabilities. Unsetting clears the branch the same way, and an element
  whose source element is still flagged cannot be unset on its own (409). `scans fp`, the console
  and `POST /api/scans/ID/fp` all follow this.
