- Shared entity tags are named only through `src/tags.rs`: the tag calls that spelled a
  registered tag as a literal (`derived`, `geoint`, `web`, `candidate`, `malicious`,
  `wikipedia-edit`, `social-profile`) use its constants, and eight constants no entity ever
  carried (`crawled`, `external`, `breach-derived`, `recalled`, `recycled`, `source-document`,
  `coarse`, `hosting`) are removed. `tests/tag_registry.rs` refuses a literal for a registered
  tag and a constant nothing uses, so the registry stays the one authority.
- The ATT&CK catalogue behind `attack status|coverage|gaps` is held to ATT&CK's structure by tests
  (well-formed, unique, sorted ids; sub-technique flags; every sub-technique's parent present and
  its tactics within the parent's; every tactic populated), so a refresh that breaks it fails
  before it skews a coverage figure.
- `examples/name_match_bench.rs`, which nothing ran, runs in CI and fails when accented names in
  capitals match differently from the same names in ASCII.
