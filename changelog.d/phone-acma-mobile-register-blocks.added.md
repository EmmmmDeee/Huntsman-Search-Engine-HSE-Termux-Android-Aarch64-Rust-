- A `phone` lookup (and the phone scan kind) of an Australian mobile now reads the ACMA numbering
  register offline: the number's block (`0405000000-0405999999`), whether the register lists it as
  allocated or spare, the original allocatee and allocation date, and the latest holder and
  transfer date, from an embedded copy of the regulator's public full download (175 mobile blocks,
  13 holders, retrieved 2026-11-03, SHA-256 recorded in `address_au`). It is numbering-plan
  enrichment, never a source that observed the number: the holder is the range's registered
  holder, not the carrier serving the number today (number portability) and not the subscriber,
  and a spare block is flagged as unlikely to be in service. No request is made.
