# Performance baseline — graph data-fabric pipeline

This file is the committed reference for `benches/pipeline.rs`, the offline,
deterministic benchmark of HSE's graph pipeline. It exists so "low-overhead /
high-velocity on aarch64" is a *measured* property, tracked over time, not an
assertion.

## How to run

```bash
cargo bench --bench pipeline                              # default: 500 entities, 50 iters
HSE_BENCH_N=2000 HSE_BENCH_ITERS=100 cargo bench --bench pipeline
```

The workload is generated in-process and deterministic — **no network, no
external data**. It exercises every relation family (structural, co-location,
resolution, registration, image similarity, stealer co-occurrence), the batched
storage upserts (one WAL transaction each), and the 35-rule correlator. Peak
RSS is read from `/proc/self/status` (`VmHWM`) on Linux/Termux.

## Reference numbers

Capture on the actual device — numbers vary by CPU. The table below is an
illustrative x86-64 dev-host run (release profile, `N≈441`); **record an
on-device aarch64 run here after the first Termux install** so regressions are
judged against real hardware.

| Stage | Median | Output |
|-------|-------:|--------|
| `derive_structural` | ~0.23 ms | 100 edges |
| `derive_colocation` | ~0.70 ms | 380 edges |
| `derive_resolution` | ~0.29 ms | 100 edges |
| `derive_registration` | ~0.01 ms | 0 edges |
| `derive_image_similarity` | ~0.03 ms | sparse |
| `derive_stealer_cooccurrence` | ~0.22 ms | 92 edges |
| **full graph build (6 builders)** | **~1.5 ms** | 673 edges |
| `upsert_entities_batch` (1 txn) | ~9.3 ms | 441 entities |
| `upsert_relations_batch` (1 txn) | ~1.2 ms | 673 relations |
| `correlator.run` (35 rules) | ~19.5 ms | 455 correlations |
| graph-build throughput | ~300k entities/sec | |
| peak RSS | ~8 MiB | |

### Reading it

- **Graph build is the hot path that matters** and is sub-millisecond-per-100s
  of entities — the recursive engine can pivot freely.
- `correlator.run` re-reads the scan from SQLite each call; in production it
  runs **once** per scan, so its cost is one-shot, not per-round.
- `derive_colocation` and `derive_image_similarity` are pairwise **O(k²)** over
  *their own* entity kind by design (the only honest way to cluster). The bench
  caps coordinates at 40 to keep that representative; on a real scan the
  per-kind counts stay modest. If a future workload makes either dominate,
  that's the signal to add spatial/LSH bucketing — the bench will show it first.

## The regression gate

Wall-time on a shared CI runner is too noisy to gate on a percentage, so CI
does **not** assert on the millisecond numbers above. Instead
[`tests/perf.rs`](../tests/perf.rs) (run by `cargo test --all`) hard-gates on
**deterministic complexity invariants** that actually protect performance:

- stealer co-occurrence is a **star** (`n-1` edges), never a mesh (`n²`);
- structural edges link the **closest parent only** (no transitive closure);
- a 1 000-entity full pipeline finishes under a **generous 30 s catastrophe
  ceiling** — loose enough never to flake, tight enough to catch an O(n²)+
  regression (observed ~70 ms on the dev host).

So: precise timing → this bench (run on-device, update the table); regression
safety → `tests/perf.rs` (enforced every CI run).
