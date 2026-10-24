- `run-history record` no longer deletes the last run in a history file that ends without a
  newline. A file holding a complete run with no final newline (an editor that saves without
  one, or a crash after the run's last byte) was listed by `run-history show`, and `record`
  measured its verdict against that run, but the append then truncated it as an interrupted
  write, so the next `show` no longer listed it. A final line that parses as a run is now kept
  and given its newline before the new run is appended; a final line that does not parse is
  still dropped as an interrupted write.
