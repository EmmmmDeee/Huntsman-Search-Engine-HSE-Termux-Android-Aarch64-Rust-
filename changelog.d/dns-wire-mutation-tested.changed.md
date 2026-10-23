- The wire-form DNS answer reader that `dns_filter` uses is now tested against 20,000 corrupted
  answers: two real resolver answers, a filtering resolver's refusal, and an answer with every
  record type. Each one is read or refused, and its records' presentation forms are written,
  without a panic. The test was checked by planting an unchecked read in the record reader, which
  it caught.
