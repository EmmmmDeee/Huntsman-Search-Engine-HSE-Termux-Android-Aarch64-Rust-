- **ACNC** and **Exa** evidence is now counted under the families meant for it. The
  correlator's match arms named `acnc_charities` and `exa_search`, IDs no collector writes, so
  ACNC charity-register evidence counted as `other` instead of `identity_registry`, and Exa
  search hits as `other` instead of `search`.
- **Wikipedia** edits no longer count as infrastructure. `wikipedia` matched the `ip` in its
  name and was classed `infra`; it is now `other`, like the other community-curated sources.
- What this changes: the family counts in the `multi_breach` (AU-001) and `api_key_exposure`
  (AU-021) messages, and the families `tagged_matching_sources` reports, for entities carrying
  that evidence. The classification snapshot changes in exactly these six rows: `acnc`, `exa`,
  `wikipedia`, and the probes `ACNC`, ` acnc ` and `Wikipedia`.
