- `network` no longer calls a locally administered BSSID randomised. The U/L bit says only that
  the maker did not assign the address: routers set it on extra SSIDs, and virtual interfaces
  set it too. The offline OUI evidence now records `locally_administered=true` and
  `randomisation_status=unverified` with no vendor, in place of `randomised=true` and the
  vendor `Randomized (private)`.
