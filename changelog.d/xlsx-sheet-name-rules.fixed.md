- An `.xlsx` export (`scans export`, `scans correlations` and `scans compare` with `-f xlsx`, and
  their `/api/scans` forms) now always names its sheets as Excel allows when a correlation rule
  is named oddly. A rule named `' '` made a blank sheet name; a name cut at 31 characters just
  after an apostrophe (`Exposed services on the vendor's network`) ended in `'`; and a U+FFFE or
  U+FFFF in a name was written raw, so the workbook was not well-formed XML and would not open.
  These now give `Sheet`, `Exposed services on the vendor` and the name without the character.
  Cell contents do not change.
