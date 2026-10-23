- Library items nothing read: `oui_ieee::registry_len`; `roi::quota_exhausted_blocked`, which
  also disagreed with the planner's live quota gate; and the per-dispatch text that was built and
  then dropped, `DispatchUtility::explanation` and `PlannedDispatch::rationale`. No output carried
  them; `plan` and `GET /api/analyze` report only counts and `final_utility`.
