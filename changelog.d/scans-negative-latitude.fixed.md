- `scans run -33.86,151.21` no longer fails with "unknown option": a word that starts with a dash
  and a digit is a value, so a southern-hemisphere `LAT,LON`, every point in Australia, can be
  scanned and saved. `sf -s` reads such a value the same way instead of saying `-s` needs one.
  `lookup_args::is_option` is the one rule both parsers use.
