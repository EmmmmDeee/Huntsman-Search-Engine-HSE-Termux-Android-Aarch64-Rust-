- `scans matrix` and the Scan page's Matrix exports no longer count a module that never sent a
  request as executed. On a phone scan with no IPQS or Numverify key, the summary credited both
  with a run, though each recorded `not_configured`.
  - **`module_execution_counts`.** It now counts only runs a module made, so a module that
    recorded `not_configured` or `refused_before_sending` is not in it.
  - **`module_outcome_kinds`.** This new field gives every module's outcomes by kind. A module
    without rows now says why: never asked, asked and validly empty, or asked without an answer.
