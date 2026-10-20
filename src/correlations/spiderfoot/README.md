# Spiderfoot 4.0 correlation rules

These 37 files are Spiderfoot's own correlation rules, copied unchanged from
[smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) `correlations/` at commit
`0f815a203afebf05c98b605dba5cf0475a0ee5fd` (Spiderfoot 4.0; `template.yaml` left out). They are
MIT licensed; `LICENSE` here is Spiderfoot's.

`src/sf_correlate.rs` embeds every file at build time and runs it over each saved scan's data
elements. Keep them as Spiderfoot ships them: a change in behaviour belongs in the engine, and an
operator's own rule belongs in `$HUNTSMAN_HOME/correlations` (or `~/.huntsman/correlations`),
where a file with a shipped rule's id replaces it.
