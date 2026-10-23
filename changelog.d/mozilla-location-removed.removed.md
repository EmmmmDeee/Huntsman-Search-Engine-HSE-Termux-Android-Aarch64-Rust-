- The Mozilla Location Service lookup is removed. Mozilla removed third-party API access on
  2024-06-12, and no lookup ever asked it anything: it was listed among the indicator legs and
  the module catalogue (`network BSSID`, ATT&CK T1590.005) without being able to run. A
  `HUNTSMAN_MOZILLA_LOCATION_KEY` left in `~/.huntsman.env` is reported by `credential-status`
  and `doctor` as retired, with the command that removes it.
