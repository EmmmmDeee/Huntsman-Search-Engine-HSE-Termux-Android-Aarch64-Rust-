- A saved scan's `source_execution_summary` (the scan detail and compare API, and the Web UI's
  coverage line) no longer counts a request Huntsman's guard refused before sending as an
  attempted, unresolved request. Such a row was never sent; it is now counted under its own
  `refused_before_sending` total, left out of `attempted`, and still keeps
  `all_recorded_sources_accepted` false. The Web UI's coverage line names the count.
