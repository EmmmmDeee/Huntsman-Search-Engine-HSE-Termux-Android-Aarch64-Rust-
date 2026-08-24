# /drift — Live API Drift Detection

Probe real third-party OSINT endpoints to detect wire-format changes.

## Usage
```
/drift              # Run full live drift sweep of all keyless modules
/drift --summary    # Show summary only (skip per-module details)
/drift <module>     # Check a specific module
```

## Classifications
- **alive** — Provider reached, parser produced ≥1 entity (healthy)
- **empty** — Provider reached, parser produced 0 entities (possible drift)
- **unreachable** — Transport error (provider down or offline)
- **timed-out** — Exceeded module's budget (provider slow)

## Canary Modules (Must-Yield)
If a **canary** module goes empty, it's confirmed wire-format drift and the run fails:
- `ip_geo` / `crtsh` / `bgpview` / `ripestat` (and others)

Non-canary empties are informational (sample may legitimately have no data).

## Output
Per-module status table with health classification. Red run = actionable drift.

## When to Run
- Weekly (via scheduled Routine)
- After adding a new OSINT module
- If a live scan comes back unexpectedly empty
- To verify a parser fix actually works

## Related
- `cargo test --test live_drift -- --ignored --nocapture` (direct command)
- `hse doctor --live` (standalone binary command)
