- `ip` (and an address `scan`) now counts a Mnemonic passive DNS request the egress policy
  refused, or one that got no response, when it says why no source answered. Mnemonic kept only
  its row, so `scans run 93.184.215.14 -m mnemonic` on a network where `api.mnemonic.no`
  resolves to `0.0.0.0` failed with `no source answered for ip 93.184.215.14` and no reason
  (exit 69). It is now a refused request (exit 77) whose message starts `mnemonic: request
  refused before sending:`. Because Mnemonic is asked before Shodan InternetDB, `ip 8.8.8.8`
  with no network at all now fails with `no source answered for ip 8.8.8.8: mnemonic: no
  response (ConnectFailure)` where it named `internetdb`, and with every request refused the
  exit-77 message starts `mnemonic: request refused` where it started `internetdb: request
  refused`. Outcome rows, entities and the JSON report are unchanged.
