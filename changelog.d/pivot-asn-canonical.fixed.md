- An AS number an indicator source names in an `ip` or `domain` lookup (ISC's `as`, Maltiverse's
  `as_number` and the other sources' AS pivots) becomes an ASN entity only when it is a public AS
  number, read as the `asn` command reads one. A private-use or reserved number, for example an
  ISC answer with `"as": 64512`, became an `AS64512` entity, a value `asn AS64512` refuses; it is
  now dropped, as a non-public pivot address is. A pivot written `ASN13335` or `AS 13335` was
  dropped and is now the entity `AS13335`. The `asn` attribute on the queried address keeps the
  provider's value either way.
- The same holds for the origin AS numbers RIPEstat names in an `ip` or `netblock` lookup: an
  origin that is not a public AS number, for example `AS64512` or `AS23456`, is no longer an ASN
  entity, and its holder no longer an organisation entity. The address's or block's RIPEstat
  record keeps every origin in its `origin_asns` attribute and its summary either way.
- The `BGP_AS_MEMBER` elements a scan saves from a record's `asn` and `origin_asns` attributes,
  which `scans elements`, `/api/scans/{id}/elements` and the exports list, follow the same rule:
  only a public AS number becomes one, written as the ASN entity is (`AS13335`). An `ip` or
  `netblock` scan whose RIPEstat answer named `AS23456` or `AS64512` beside `AS13335` saved
  `AS23456` or `AS64512` as an AS the address or block belongs to; it now saves `AS13335` only.
  A scan saved earlier keeps the elements it was saved with.
