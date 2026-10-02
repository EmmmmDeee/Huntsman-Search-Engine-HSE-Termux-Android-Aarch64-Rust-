# Claude Code HSE — Quick Reference

## ⚡ Fastest Workflow

**Keybindings you'll use every day:**
```
Ctrl+G              Run gate validation (fmt + clippy + tests in ~30s)
Ctrl+Shift+T        Run full test suite
Ctrl+T              Start the app
Ctrl+Shift+L        Start 5-minute testing loop
```

## 🔍 Common Commands

### Validate Code Quality
```bash
/ci --quick         Fast validation (skip MSRV/cross-build)
/ci                 Full validation (5+ min)
```

### Detect API Drift
```bash
/drift              Sweep all modules against live providers
/drift <module>     Check single module
```

### Verify Documentation
```bash
/doc-drift          Compare docs against code values
```

### Query the Codebase
```bash
/find-modules       List all OSINT modules
/grep <pattern>     Search code
/read <file>        Quick file view
```

## 📊 What's Different Now

| Before | Now |
|--------|-----|
| Manual tool prompts | Pre-approved allowlist (10 fewer prompts/session) |
| Haiku model | Opus 4.1 (better reasoning) |
| No validation hook | Pre-push gate (fail early, fail locally) |
| Typing commands | Ctrl+G for common operations |
| No cached context | 500MB prompt cache (faster repeat queries) |

## 🎯 Development Loop

### Adding a New Module
```bash
# 1. Create the module
edit src/modules/new_module.rs

# 2. Validate syntax
Ctrl+G              # Quick gate

# 3. Run tests
Ctrl+Shift+T

# 4. Check for drift
/drift new_module

# 5. Push
git add .
git commit -m "Add new_module OSINT source"
git push             # Pre-push hook validates automatically
```

### Fixing API Drift
```bash
# 1. Detect drift
/drift

# 2. Find the broken module
# (check output for "empty" classification)

# 3. Edit parser
edit src/modules/<module>/mod.rs

# 4. Test parser against fixtures
Ctrl+Shift+T

# 5. Verify drift is fixed
/drift <module>

# 6. Commit and push
git add .
git commit -m "Fix <module> API drift"
git push
```

### Code Review & Refactor
```bash
# 1. Run full validation
/ci

# 2. Check determinism
/run (scan then export to verify)

# 3. Update docs if needed
edit docs/README.md

# 4. Verify docs match code
/doc-drift

# 5. Push
git push
```

## 🔧 Configuration

### Change Model
Edit `.claude/settings.json`:
```json
"model": "claude-opus-4-1-20250805"  // or any other model
```

### Add Keybinding
Edit `.claude/settings.json`:
```json
"keybindings": {
  "ctrl+g": "run /ci",
  "your_key": "run your_command"
}
```

### Disable Pre-push Hook
Edit `.claude/settings.json`, remove `StopBeforePush` from hooks.

## 📚 Reference

- **Full upgrade details:** `.claude/UPGRADE_SUMMARY.md`
- **Gate command:** `/ci` (or `.claude/commands/ci.md`)
- **Drift detection:** `/drift` (or `.claude/commands/drift.md`)
- **Doc sync:** `/doc-drift` (or `.claude/commands/doc-drift.md`)
- **HSE Drift Agent:** `.claude/agents/hse-drift-watcher.md`

## 🆘 Troubleshooting

**Pre-push hook too strict?**
- Run gate manually to debug: `scripts/gate.sh --quick`
- Temporarily disable: remove `StopBeforePush` from settings
- Force push (rare): `git push --no-verify`

**Keybinding not working?**
- Verify `.claude/settings.json` syntax (run `python3 -m json.tool .claude/settings.json`)
- Restart Claude Code
- Some IDEs override keybindings

**Model too slow?**
- Use `Ctrl+C` to cancel if needed
- Switch to `claude-sonnet-5` for faster responses (trade off reasoning)
- Prompt cache helps on repeated queries (no wait on re-runs)

---

**Last updated:** 2026-08-21  
**Claude Code Version:** Latest (Opus 4.1)  
**Status:** ✅ Ready
