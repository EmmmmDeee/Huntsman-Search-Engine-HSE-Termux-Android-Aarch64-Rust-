- Save STAC satellite catalogue and OpenSky aircraft observations under their own
  Rust collector components in geocode ledgers, rather than attributing both to
  the Nominatim lookup front-end. Preserve source names, fallback attribution
  and hash-chain structure, with regression tests for every recorded claim.
