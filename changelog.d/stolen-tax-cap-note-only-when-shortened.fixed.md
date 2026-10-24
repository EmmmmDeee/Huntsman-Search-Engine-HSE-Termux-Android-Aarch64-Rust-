- A stolen.tax path that got no response notes `request capped at …s, the rest of the 120s
  lookup budget` only when the cap shortened the request by at least the tenth of a second the
  note prints. A cascade's first request is capped at the 120 s request ceiling less the
  microseconds the lookup has already spent, so its failure read `no response (ConnectFailure);
  request capped at 120.0s, the rest of the 120s lookup budget` in the exposure row, the
  `recon stolen-tax` summary and a saved scan's log, claiming a cap that shortened nothing. It
  now reads `no response (ConnectFailure)`; a request the budget did shorten keeps the note.
