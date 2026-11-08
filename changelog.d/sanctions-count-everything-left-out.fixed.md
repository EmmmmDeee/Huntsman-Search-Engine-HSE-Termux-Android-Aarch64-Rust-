- The sanctions lists never report a complete result they did not deliver: a name match past the
  50-listing cap is counted in the outcome detail ("N more matching listings beyond the first 50
  were not attached"), and list rows that could not be parsed (wrong column count, no id, no name)
  are counted and make the outcome `inconclusive` rather than a clean `valid_zero` when nothing
  readable matched. A row that could not be read may hold the subject.
