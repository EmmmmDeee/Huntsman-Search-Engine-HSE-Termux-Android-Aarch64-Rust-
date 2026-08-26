# SeekNow Credential & Session Hygiene

**Operational practices for managing your own SeekNow authentication safely — token rotation, multi-device isolation, and API key segmentation.**

This document covers hardening practices for *your own* SeekNow account and
credentials. It does not cover, and HSE does not provide, techniques for
defeating another party's bot detection, rate limiting, or authentication —
see [`docs/SEEKNOW_WEB_AUTOMATION.md`](SEEKNOW_WEB_AUTOMATION.md) for the
supported, ToS-compliant authentication paths (API key, or manual browser
login with local session persistence).

---

## 1. Credential Rotation & Expiration Management

**Checking account/key health:**

```bash
# hse doctor probes /credits live and prints a "SeekNow account" section
# (plan tier, remaining credits, whether the configured key is being rejected)
hse doctor
```

**Rotating your key:**

HSE reads a single `HUNTSMAN_SEEKNOW_KEY` from `~/.huntsman.env` — there is
no automatic token refresh or expiry tracking on HSE's side. To rotate:

```bash
# 1. Generate a new key at https://see-know.ru (account dashboard)
# 2. Replace the value in ~/.huntsman.env
hse set-key HUNTSMAN_SEEKNOW_KEY <new-key>
# 3. Revoke the old key from the SeekNow dashboard once confirmed working
hse doctor
```

If you use the web-automation login path instead of an API key, see
[`docs/SEEKNOW_WEB_AUTOMATION.md`](SEEKNOW_WEB_AUTOMATION.md) — re-running
that login flow is currently a manual step, not something HSE triggers
automatically on a schedule.

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

HSE currently reads exactly one SeekNow key (`HUNTSMAN_SEEKNOW_KEY`) — there
is no built-in per-scan-type key selection to segment blast radius within a
single install. If you want that isolation, it has to be done at the install
level: run separate HSE configs (separate `HUNTSMAN_INSTALL_DIR`/env files),
each with its own SeekNow key, and route different scan types to whichever
instance holds the appropriate key.

If a key is leaked, revoke and rotate it — see §1 above.

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
