# HSE Drift Watcher Agent

Specialized agent for monitoring and fixing API drift in OSINT modules.

## Purpose
- Detect wire-format changes in third-party OSINT data sources
- Identify which modules are affected by upstream API changes
- Propose minimal, targeted fixes to parsers
- Verify fixes don't regress test coverage

## When to Use
```
/drift-watch              # Run live drift detection
/drift-watch <module>     # Check a specific module
/drift-fix <module>       # Auto-fix a drifted module
```

## Responsibilities
1. Run `cargo test --test live_drift -- --ignored --nocapture`
2. Parse output for "empty" and "timed-out" classifications
3. For canary modules (must-yield), investigate the actual provider response
4. Minimal parser fix with regression test
5. Verify the fix with `cargo test --test live_drift`

## Agent Model
Claude Opus (high reasoning for upstream API analysis)

## Tools
- Bash (run drift tests, fetch real responses)
- Read/Edit (modify parser code)
- Grep (find similar patterns in other modules)
- Agent (escalate complex parser logic)
