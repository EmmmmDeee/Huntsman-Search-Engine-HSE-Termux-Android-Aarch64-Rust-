- A provider key sent as a query parameter now goes into the query of a URL that has a
  `#fragment`. Before, it was appended after the fragment, so it was never sent, while the
  result still recorded the key as sent and read a 401 as the key being rejected.
- A `Retry-After` of more seconds than fit in 64 bits is read as the longest wait, capped as
  every other long wait is, instead of as no wait at all.
- Public-only egress refuses three IPv6 ranges IANA marks not globally reachable: the local-use
  NAT64 prefix `64:ff9b:1::/48` (RFC 8215), which a network's own translator can map to private
  IPv4, benchmarking `2001:2::/48` and documentation `3fff::/20` (RFC 9637).
- A URL written `scheme:user:pass@host/` (without `//`) has its userinfo dropped from errors and
  logs, as one written with `//` already had.
- An EXIF GPS coordinate past 90 degrees of latitude or 180 of longitude, or with 60 or more
  minutes or seconds, gives no fix rather than an impossible one, as XMP coordinates already did.
