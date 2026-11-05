- `docs/CONSOLIDATION_PLAN.md` plans the consolidation and refactor of the engine without
  regression. Every figure in it was measured at `e7301b4c6`. It covers:
  - **Duplicated authority.** Four source classifiers are kept in step by nothing. Two of
    their entries are typos that miss the `acnc` and `exa` collectors, and `wikipedia` is
    classed as infrastructure because its name contains "ip".
  - **Saved attribution.** Saved lookups credit any collector without its own row to the CLI
    file.
  - **"No source answered".** Three mechanisms decide it, and seven lookups end a refusal with
    the bare egress reason, naming no module.
  - **The fix.** One source profile table, an account-leg kernel, one CLI finish path and shared
    test transports.
  - **Safeguards.** A non-regression contract, phases with exit conditions, six guards, and the
    four output changes it allows, each declared in advance.
