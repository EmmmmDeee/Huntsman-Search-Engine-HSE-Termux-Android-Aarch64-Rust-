# /doc-drift — Documentation Drift Detection

Verify that documentation values stay synchronized with code.

## Usage
```
/doc-drift          # Check all docs against code values
/doc-drift --fix    # Auto-update docs to match code (if safe)
```

## What It Checks
- Module count claims vs actual registry
- OSINT endpoint credit prices vs code
- API constants referenced in guides
- Per-module confidence/limit estimates

## Why This Matters
Example: SeekNow price table changed in code (`/search/deep` 3→1 credit) but 
operator docs kept quoting the old price. A customer budgeting a scan would 
have overestimated costs by 3×. Doc drift can silently break operator ROI calculations.

## Guarded Values
Docs that quote SeekNow prices:
- `docs/ENTERPRISE_GUIDE.md`
- `docs/HIGH_VALUE_QUERY_SYSTEM.md`

## When to Run
- After any code constant change
- When updating operator documentation
- As part of CI before release
- To audit existing docs for staleness

## Related
- `cargo test --test doc_drift -- --ignored --nocapture` (direct command)
