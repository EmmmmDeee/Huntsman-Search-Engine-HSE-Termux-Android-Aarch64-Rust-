- `people NAME` (and the people leg of `scan`) no longer reports a cut-off ASIC register answer
  as a clean miss. Each register is asked for at most 100 records. When the answer said more
  matched (CKAN's `total`, say 340 for `people "John Smith"`) and none of the 100 read carried
  the name, the `asic_persons.advisers` row read `valid_zero` with `found=0`, as if the register
  had been searched and held nobody of that name. The row keeps its kind and count but now carries
  `detail=partial: read the first 100 of 340 matching records; absence of a record here is not
  evidence of absence`, and the saved or JSON outcome's `detail` holds the same text. A unit test
  in `src/asic_persons.rs` holds it and fails on the previous code. A page cut short that does hold matches keeps its kind and count too and carries the same note, for example `success found=1 detail=partial: read the first 100 of 340 ...`.
