- Every browser-facing `serve` route (lookup, Wi-Fi radar, scans, key settings, analysis, file
  inspection) refuses a cross-site fetch, and a request without the page's
  `X-Huntsman-Lookup: 1` header, through one guard and in the same words
  (`cross-site NOUN refused`, `NOUN needs the X-Huntsman-Lookup: 1 header`). The bearer-token and
  loopback `Host` checks are one function each, shared by the router and the upload gate, so the
  gate that decides whether to read an upload cannot drift from the route that answers it.
