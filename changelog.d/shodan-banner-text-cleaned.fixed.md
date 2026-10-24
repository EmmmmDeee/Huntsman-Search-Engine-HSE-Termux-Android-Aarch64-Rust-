- Shodan banner text is trimmed before a product and its version are joined, and a true or false
  value is kept. A banner with product `nginx ` and version `1.18.0` was listed in `services` as
  `443/tcp nginx  1.18.0`, with two spaces, and one with a blank product and version `2.4` as
  `80/tcp   2.4`; they now read `443/tcp nginx 1.18.0` and `80/tcp 2.4`, and `products` likewise.
  A `true` or `false` where Shodan usually writes text or a number (a banner field, a place code
  or a CVSS score) was dropped and is now kept as `true` or `false`.
