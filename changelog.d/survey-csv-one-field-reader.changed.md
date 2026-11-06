- The four Network Survey importers (Bluetooth, Wi-Fi, LTE and NR) read their fields through one
  set of readers in `src/rf/survey_csv.rs`: the column lookup, a bounded whole number, a finite
  measurement within its range and bounded text. Each importer had its own copy of each. Every
  export is accepted or refused exactly as before: 4,140 edited copies of each importer's
  accepted row, one field changed to an edge value each time, give byte-identical output before
  and after. New contract tests in `src/rf/survey_csv.rs` pin the shared readers.
