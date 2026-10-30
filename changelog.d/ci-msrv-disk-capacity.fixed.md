- Prevent Rust 1.87 and 1.99 CI test-matrix runners from exhausting disk while
  linking the full workspace test suite: disable incremental compilation and
  debug symbols for these ephemeral verification jobs, without skipping any
  check. Print disk headroom before and after acceptance, including on failure.
