- The `domain` lookup (and the domain arm of `scan`) now decides how it ends from its source rows
  through `source_outcome::SourceReach`, like `ip`, instead of a side channel only two of its many
  legs wrote. A domain lookup no source answered now ends from whichever row stopped it:
  - any chosen source refused before sending (the guarded egress dropped the request) now makes
    the lookup a refusal — exit 77 with that row's reason — where before only crt.sh could set the
    refusal and every other refused leg (the DNSBLs, the DoH filters, the threat feeds, the keyed
    and indicator sources) fell through to exit 69 with the generic `no source answered for domain
    …` and no reason;
  - a source reached but silent is still exit 69, now `no source answered for domain …: <row>`
    naming the first such row.
  A source that answered, even "nothing known" (a validated zero) or with an error, still prints,
  exactly as before; a lookup that found any entity still prints. The decision itself is unchanged
  — a lookup prints unless it has no entity and no source answered — only the reason it gives when
  it stops is now read from the rows.
- `domain_cli` drops its private `Found` accumulator (the module's own `Report` replaces it) and
  the `refused`/`unanswered` side channels on it; `crtsh_leg` collapses its two error arms, and
  `dns_leg` and the keyed/indicator legs stop writing the side channel. Each leg's row carries its
  own reason, read like any other row.
