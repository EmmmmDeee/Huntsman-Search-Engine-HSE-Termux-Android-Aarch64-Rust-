- A long-running `serve` no longer keeps a circuit breaker for every host it has ever reached.
  The table holds at most 2,048 hosts. A new host past that drops the least recently used one
  whose breaker is closed; a host still being backed off is dropped only when no breaker is
  closed.
