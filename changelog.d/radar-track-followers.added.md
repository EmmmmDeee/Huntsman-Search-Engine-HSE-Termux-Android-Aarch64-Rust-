- `radar track` adds one cached Wi-Fi sweep, placed at the registered serving cell, to a private
  sweep log (`$HUNTSMAN_HOME/radar/sweeps.jsonl`, newest 256 sweeps), and reports the stable
  BSSIDs that recur across sweeps and those heard in three or more distinct cells over at least
  ten minutes: a device that moved with you. This wires the `radar` module's cross-sweep
  recurrence and follower detection, which nothing called, into the shipped `radar` command;
  randomized and locally administered addresses are never logged or flagged.
