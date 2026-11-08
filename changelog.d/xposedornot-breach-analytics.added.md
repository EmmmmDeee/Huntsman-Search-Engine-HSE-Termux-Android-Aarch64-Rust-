- The keyless XposedOrNot breach lookup now uses the richer breach-analytics endpoint, amplifying
  each address's exposure: every public breach is kept with its exposed-data categories, breach
  date, record count, industry and verified flag, plus an overall risk label and score, alongside
  the breach names and count it already reported. No record content or credential value is kept —
  a "Passwords" entry is the category of data a breach exposed, never a password. An address in no
  breach stays a clean valid-zero; a malformed body is a failure, never a zero.
