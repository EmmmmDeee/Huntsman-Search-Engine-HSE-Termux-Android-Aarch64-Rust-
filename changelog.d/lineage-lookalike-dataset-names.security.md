- One upstream dataset can no longer be counted as two independent sources by how its name is
  spelled. Dataset and collector family names now drop invisible characters (zero-width spaces
  and joiners, bidi controls, variation selectors, soft hyphens), fold fullwidth and
  mathematical letters to ASCII, and, in a name that presents as Latin, fold every letter
  Unicode's UTS #39 confusables map to one ASCII letter or digit, so `Adobe`, `\u{0410}dobe`
  (Cyrillic A) and `Ado\u{200B}be` are one family and cannot corroborate each other. A name
  with no ASCII letter keeps its own script. The table is generated from Unicode's files by
  `cargo run --locked -p xtask -- confusables generate`.
