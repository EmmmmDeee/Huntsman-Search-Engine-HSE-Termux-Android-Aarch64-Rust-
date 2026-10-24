- `modules` no longer lists `au_people` and `au_electoral` as `people NAME` modules. Both sources
  were deleted and `people` asks only `asic_persons` and `asic_director`, yet both rows were still
  shown as reachable and counted, in `modules --json`, `GET /api/modules`, the New Scan module
  list, `sf -M` and the `diagnostics` module counts too. Choosing `au_people` (or
  `sfp_au_electoral`) for a scan of `Jane Citizen` used to pass module selection and then be
  refused with "none of the chosen modules (au_people) looks up the target"; it is now refused at
  once with "no module is named au_people". `attack status`, `coverage`, `gaps` and `navigator`
  no longer count ATT&CK T1589.003 (Employee Names) as covered by those two rows: no network
  module gathers it now, so it is reported as a gap.
