# Runtime independence, parity & code-driven output

**Baseline requirement: HSE runs, and produces every result, on Termux
Android aarch64 (non-root) with no AI, ML, LLM, cloud inference, agent
framework, vector database, embedding model, or external reasoning service
available at runtime.**

AI assistance (parallel agents, automation, advanced tooling) is welcome — and
used — **during development**: writing code, auditing, researching data sources,
generating and reviewing tests. It is a *development accelerator*, never a
*runtime dependency*. Anything an AI helps produce is converted into
maintainable, documented, deterministic Rust before it ships.

## The guarantees

1. **No AI at runtime.** The compiled `hse` binary carries zero AI/ML/LLM/
   inference/vector/embedding crates, weights, or model files, and makes no calls
   to hosted AI / embedding / completion / agent services. (External *OSINT data*
   APIs — registries, breach corpora, geocoders — are data sources, not AI
   services, and are unaffected by this charter.)
2. **Deterministic, reproducible output.** Every conclusion, correlation, score,
   ranking, and finding is derived by explicit Rust logic from the available
   inputs, configuration, data sources, and source code. Given the same inputs
   and the same code, the same outputs result — on any platform.
3. **Environment parity.** Results on Termux aarch64 (non-root), Linux, CI, and
   dev machines come from the **same** Rust logic and data-processing rules.
   There is no privileged "smart" path that only exists where an AI is present.
4. **Transparency over inference.** Confidence and correlation come from
   documented, inspectable heuristics and rules — not opaque models. Decision
   rationale, confidence math, correlation pathways, and evidence chains are
   recorded so any output can be traced back to code + data.

## Where the determinism lives (code, not magic)

- **Confidence fusion** — `Entity::c_effective` (`src/core/entity.rs`): a
  closed-form noisy-OR / multiplicative model over the count of *distinct*
  corroborating sources, `max(C·(1+0.15·ln n), 1−(1−C)·0.65^(n−1))`. Pure
  function; no training, no inference.
- **Correlation** — the `AU-0xx` rules in `src/core/correlator/rules.rs`: each is
  a hand-written, named, documented rule (e.g. AU-033 links an ABN/ACN to its
  registered organisation by registry tag). Inspectable and unit-tested.
- **Heuristics** — e.g. `breach_timezone::infer_timezone` is a deterministic
  histogram over breach-activity hours, not an ML "inference"; name permutation,
  postcode→locality expansion, and geo-coherence weighting are all explicit
  algorithms.
- **Evidence** — every entity carries its full source records (`source`,
  attributes, summary) so a finding is reproducible from its evidence chain.
  Nothing is redacted or omitted.

## How it is enforced (verifiable through Rust execution)

The principle is not aspirational prose — it is a CI guard:

- `tests/architecture.rs::runtime_carries_no_ai_ml_inference_dependency` parses
  `Cargo.lock` and fails the build if any AI/ML/LLM/inference/vector/embedding
  crate (candle, burn, tch, tract, ort/onnx, an LLM SDK, tokenizers/tiktoken,
  qdrant/pinecone/lance/hnsw/…) enters the dependency tree.
- The existing invariants reinforce it: `#![forbid(unsafe_code)]`, rustls-only /
  bundled-sqlite (no C/native services), and `core ⊥ util/storage` boundaries.

Reproduce the audit yourself:

```bash
grep -E '^name = ' Cargo.lock | wc -l          # full dependency inventory
cargo test --test architecture                 # runs the AI-independence guard
cargo build --release --locked                 # the artifact that runs on-device
```

## When AI contributes to development

Acceptable: using AI to draft a module, find bugs, validate data sources, or
write tests. Required before integration: the result is rewritten as
maintainable, documented, deterministic Rust; passes `cargo fmt`, `clippy -D
warnings`, and the full suite; and is validated to work with **all AI-assisted
tooling absent from the runtime**. Success is measured by runtime capability,
evidence quality, reproducibility, transparency, portability, and resilience —
i.e. by the value produced and verifiable through Rust code, with Termux aarch64
(non-root) as the baseline.
