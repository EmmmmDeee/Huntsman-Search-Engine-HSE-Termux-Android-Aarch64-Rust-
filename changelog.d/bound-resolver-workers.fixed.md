# Bound native DNS resolver workers

Fixes unbounded thread accumulation in system_resolve after caller timeouts.

- Added MAX_RESOLVER_WORKERS = 4 capacity guard with AtomicUsize and Drop permit.
- Saturation returns explicit DnsFailure instead of accumulating detached workers.
- Preserves existing timeout and no-address behavior.
- Addresses issue #1400 / R-03.

No new dependencies. Reversible.
