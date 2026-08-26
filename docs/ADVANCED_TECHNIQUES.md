# SeekNow Credential & Session Hygiene

**Operational practices for managing your own SeekNow authentication safely — token rotation, multi-device isolation, and API key segmentation.**

This document covers hardening practices for *your own* SeekNow account and
credentials. It does not cover, and HSE does not provide, techniques for
defeating another party's bot detection, rate limiting, or authentication —
see [`docs/SEEKNOW_WEB_AUTOMATION.md`](SEEKNOW_WEB_AUTOMATION.md) for the
supported, ToS-compliant authentication paths (API key, or manual browser
login with local session persistence).

> **⚠️ §1 and §3 below describe mechanisms HSE does not have**, verified
> against current `src/`: no `--verbose` flag exists on `hse doctor` (its
> only flag is `--live`), so it cannot show a session-age line; more
> fundamentally, per `SEEKNOW_WEB_AUTOMATION.md`'s own warning, nothing in
> `src/modules/see_know/` reads `~/.huntsman/seeknow_session.txt` at all yet
> — there is no session to refresh or force-expire. §3's
> `HUNTSMAN_SEEKNOW_KEY_EMAIL`/`_USERNAME`/`_INFRASTRUCTURE` env vars and
> "hierarchical key selection" don't exist in source either — HSE reads one
> `HUNTSMAN_SEEKNOW_KEY`, not a per-scan-kind set (`--kind`/`--value`
> themselves ARE real flags; it's the per-kind key routing that isn't). The
> shell snippets below will run without erroring — they just don't do what
> the surrounding prose claims.

---

## 1. Credential Rotation & Expiration Management

**HSE's built-in session management:**

```bash
# Check token age
hse doctor --verbose
# Shows: "SeekNow session last refreshed: 2h ago"

# Force token refresh
rm ~/.huntsman/seeknow_session.txt
# HSE will re-authenticate on next scan

# Implement 30-day rotation cron job (Linux/Termux)
cat > ~/.huntsman/rotate-tokens.sh <<'EOF'
#!/bin/bash
# Rotate SeekNow token monthly
COOKIE_FILE="$HOME/.huntsman/seeknow_session.txt"
if [ -f "$COOKIE_FILE" ]; then
    AGE_DAYS=$(( ($(date +%s) - $(stat -c %Y "$COOKIE_FILE")) / 86400 ))
    if [ $AGE_DAYS -gt 30 ]; then
        echo "Token expired, manual re-login required at https://see-know.ru"
        rm "$COOKIE_FILE"
    fi
fi
EOF

chmod +x ~/.huntsman/rotate-tokens.sh

# Run daily
echo "0 0 * * * $HOME/.huntsman/rotate-tokens.sh" | crontab -
```

## 2. Multi-Device Session Isolation

**Prevent a compromised device's token from affecting your other devices:**

```bash
# Use device-specific token identifiers
mkdir -p ~/.huntsman/sessions/$(hostname)-$(date +%Y%m%d)

# Create device-specific session
echo "TOKEN_FOR_$(hostname)" > ~/.huntsman/sessions/device-$(hostname).txt

# Rotate on device compromise
rm -r ~/.huntsman/sessions
# Forces re-authentication on all devices
```

## 3. API Key Segmentation

**If using API keys, segment by scan type so a leaked key has a bounded blast radius:**

```bash
# Different keys for different operations
export HUNTSMAN_SEEKNOW_KEY_EMAIL="seek-key-for-email-scans"
export HUNTSMAN_SEEKNOW_KEY_USERNAME="seek-key-for-username-scans"
export HUNTSMAN_SEEKNOW_KEY_INFRASTRUCTURE="seek-key-for-domain-scans"

# HSE respects hierarchical key selection
hse scan --kind email --value user@example.com  # Uses _EMAIL key
hse scan --kind username --value octocat        # Uses _USERNAME key
```

If a single key is leaked, revoke and rotate just that key — the others keep
working.

## 4. Never Commit Credentials

Credentials (API keys, the web-automation email/password) belong in
environment variables or `~/.huntsman.env`, never in source. See
[`docs/SEEKNOW_SETUP.md`](SEEKNOW_SETUP.md) for the supported configuration
variables. If a credential is ever committed by mistake, treat it as
compromised: rotate it immediately (deleting the line does not remove it
from git history).

---

## References

- **SeekNow ToS:** https://see-know.ru/terms
- **OWASP Authentication Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
