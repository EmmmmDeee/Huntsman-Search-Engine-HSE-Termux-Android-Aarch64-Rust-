- Clear graph retry permission before each handler invocation so a permanent panic
  or malformed output cannot inherit an earlier transient failure's retry flag.
  Checkpoint resume preserves these failures without repeating the handler or
  charging additional resource units; explicit transient retries remain supported.
