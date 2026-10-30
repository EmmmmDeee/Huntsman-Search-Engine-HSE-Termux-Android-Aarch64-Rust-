- The SeekNow leg and `dehashed search --save-artifact` now ask for a handle as it was written,
  not by its identity key. The key folds case and strips `.`, `_` and `-`, so `john.doe_99` was
  asked for as `johndoe99`, which is another handle. SeekNow then merged that account's records
  into the report, or spent credits on a false not-found, and the DeHashed artifact searched
  `username:"johndoe99"` while labelled `John.Doe_99`. A record that echoes the asked handle in
  another case or with other separators is the selector itself, not a pivot from it. Both
  collectors take these rules from one place, `collector::query_text` and
  `collector::differs_from_selector`.
