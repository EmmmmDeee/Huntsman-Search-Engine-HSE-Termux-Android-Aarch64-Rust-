- The keyless XposedOrNot breach leg now feeds the shared exposure scorer the same tags the keyed
  breach legs do. A breach whose exposed-data categories include passwords tags the address
  password-at-risk, and paste exposure tags it paste-exposed (a paste-only address no longer
  carries the breach tag). Without any breach key, an address exposed in a password breach now
  scores as credentials-at-risk instead of a plain breach. The leg's decoding is split into
  focused helpers with no change to what it reports.
