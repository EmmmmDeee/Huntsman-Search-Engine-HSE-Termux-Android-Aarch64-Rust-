- When the installer builds from source on a phone, it now runs one compile job per GiB of
  available memory, at most one per CPU and at least one. Cargo's default is one job per CPU,
  which on an eight-core phone with about 2 GiB free started eight release `rustc` processes at
  once, enough for Android's low-memory killer to end Termux mid-build. An explicit
  `CARGO_BUILD_JOBS` is kept, and when the available memory cannot be read Cargo's default stands.
