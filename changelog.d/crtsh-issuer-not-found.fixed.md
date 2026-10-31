- A domain's certificate log is no longer lost when crt.sh lists a certificate from an issuer it
  has no record of. crt.sh writes `-1` as that certificate's CA id and names the issuer "Issuer Not
  Found" (one of the 81 certificates it logs for `example.com` on 2026-10-31); the decoder took the
  CA id as an unsigned number, so that one row failed the whole answer, and `domain`, `scan` and a
  crawl reported crt.sh as inconclusive with none of the names or certificates it lists. Such a row
  is now a certificate like any other, its issuer kept as crt.sh names it and no CA id recorded
  for it.
