- With no key, the `ip` lookup's VirusTotal and AbuseIPDB legs and the `domain` lookup's
  VirusTotal and Hunter legs now leave a `not_configured` row, as every other keyed source does.
  Before, they left no row, so a saved scan or report could not show that they were never asked.
  One rule, `Api::unasked_for_want_of_a_key`, now writes that row for every keyed leg.
