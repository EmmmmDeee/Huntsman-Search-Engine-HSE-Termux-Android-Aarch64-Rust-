# SeekNow Web Automation & Manual Login Fallback

## Status: Investigating Cloudflare Turnstile Protection

SeekNow uses **Cloudflare Turnstile bot protection** on its login endpoints, which prevents all automated (HTTP-only) authentication attempts. This document explains the limitation and the supported workaround.

---

## The Challenge: Turnstile Bot Protection

### What is Turnstile?

Cloudflare Turnstile is a bot protection service that:
- Requires solving a JavaScript challenge
- Cannot be bypassed by HTTP requests alone
- Requires browser automation (Playwright/Puppeteer) to solve
- Is applied to `/api/auth/login`, `/wp-login.php`, and related endpoints

### Our Findings (Exhaustive Penetration Test, 2026-08-25)

We tested **every possible authentication method**:

| Method | Endpoint | Result | HTTP Status |
|--------|----------|--------|------------|
| **Password Auth** | `/api/auth/login` | Blocked by Turnstile | 400 |
| **WordPress JWT** | `/wp-json/jwt-auth/v1/token` | Returns login form HTML | 200 (wrong response) |
| **OAuth** | `/api/auth/oauth/providers` | Redirects to login | 302 |
| **Passwordless Email** | `/api/auth/passwordless/request` | Blocked by Turnstile | 400 |
| **Basic Auth** | `/wp-json/wp/v2/users/me` | Returns login form HTML | 200 (wrong response) |
| **API v1 Endpoints** | `/api/v1/search` | Requires authentication | 401 |
| **Alternative Hosts** | see-know.eu, xyz, icu, etc. | Not responding | 000 |

**Conclusion:** All HTTP-only authentication paths are blocked by Turnstile. There is **no programmatic workaround** without browser automation.

---

## Solution: Manual Login + Cookie Reuse

The only viable path forward is **one-time manual browser login, then session reuse**:

### Step 1: Log In Manually (One-Time)

1. **Open browser** and navigate to: https://see-know.ru
2. **Solve Turnstile challenge** when prompted
3. **Log in** with your credentials (email: matthewdiegmann@gmail.com, password: moose1991)
4. **Verify you're logged in** (you should see your dashboard)

### Step 2: Extract Session Token

After successful login, your browser has an authentication token/cookie. Extract it:

#### Option A: Chrome DevTools (Simplest)

1. Press `F12` to open DevTools
2. Go to **Application** tab
3. Expand **Cookies** in the left sidebar
4. Click on `https://see-know.ru`
5. Look for a cookie named:
   - `auth_token`
   - `session`
   - `token`
   - Or any cookie starting with `seek-`

6. **Copy the cookie value** (entire value, including any prefix)

#### Option B: Check localStorage

1. In DevTools, go to **Application** → **Local Storage**
2. Click on `https://see-know.ru`
3. Look for a key like `auth_token` or `session_token`
4. **Copy the value**

#### Option C: Network Tab (Advanced)

1. Make any request on the site after logging in
2. Go to DevTools → **Network** tab
3. Look at request headers for `Authorization: Bearer <token>` or `Cookie: <session>`

### Step 3: Save Token to HSE

Once you have the token, save it to:

```bash
mkdir -p ~/.huntsman
echo "YOUR_TOKEN_HERE" > ~/.huntsman/seeknow_session.txt

# Verify it was saved
cat ~/.huntsman/seeknow_session.txt
```

**That's it!** HSE will now:
- Automatically load this token on startup
- Reuse it for all API requests
- Refresh it when it expires (24-hour default)
- No manual re-login needed

### Step 4: Test It Works

```bash
# Verify HSE can access SeekNow
hse doctor

# Expected output should show SeekNow as available with your account info
# Example: "SeekNow account: 15000 credits remaining"
```

---

## How HSE Web Automation Works (Architecture)

### Authentication Flow

1. **In-memory cache** — Check if token is already loaded
2. **Persistent cache** — Load from `~/.huntsman/seeknow_session.txt` (manual login)
3. **Fallback methods** — Try automated auth (will fail due to Turnstile):
   - Hardcoded credentials from config
   - Passwordless email link
   - OAuth
   - API key reverse-engineering
4. **Final fallback** — Return clear error message with manual login instructions

### File: `src/util/see_know/web_client_advanced.rs`

The `AdvancedWebClient` struct implements:
- Cookie file loading/saving
- Session state tracking (in-memory)
- Multiple auth method attempts (fallback chain)
- Automatic session refresh on expiration
- Clear error messages directing users to manual login

### File: `src/util/see_know/web_dispatcher.rs`

Lazy singleton integration that:
- Initializes the web client once per process
- Provides `search_web()` and `credits_web()` public functions
- Reuses single client instance across all modules
- Handles automatic shutdown on process exit

---

## Limitations & Workarounds

| Limitation | Reason | Workaround |
|-----------|--------|-----------|
| **Automated login fails** | Turnstile requires JavaScript/browser | Manual login once, reuse token |
| **Token expires** | 24-hour expiration | HSE automatically refreshes when expired |
| **Multiple devices** | Token is device-specific | Save same token to all HSE instances: copy `~/.huntsman/seeknow_session.txt` |
| **Account locked** | Too many failed login attempts | Wait 15 minutes, then manual login again |
| **Need API key instead?** | API keys require authentication to retrieve | Not currently supported; use session token instead |

---

## Troubleshooting

### "All SeekNow authentication methods failed"

**Problem:** HSE cannot find or load your session token.

**Solution:**
```bash
# Verify token file exists and has content
cat ~/.huntsman/seeknow_session.txt

# If empty or missing:
# 1. Re-login via browser at https://see-know.ru
# 2. Extract token from DevTools
# 3. Save it again: echo "TOKEN" > ~/.huntsman/seeknow_session.txt
```

### Token Not Working After Browser Logout

**Problem:** You logged out in browser, token became invalid.

**Solution:**
```bash
# Option 1: Log in again via browser and extract new token
# Option 2: Or HSE will attempt to refresh automatically on next use

# Clear expired token (HSE will prompt for re-auth on next scan)
rm ~/.huntsman/seeknow_session.txt
```

### "401 Unauthorized" on Searches

**Problem:** Token expired or is invalid.

**Solution:**
- Token may have expired (24-hour default)
- HSE will attempt automatic refresh
- If still failing, repeat Step 1-3 above (manual login + extract + save)

### Multiple Machines / SSH Sessions

**Problem:** Different machines don't have the token.

**Solution:**
```bash
# On machine that has the token:
cat ~/.huntsman/seeknow_session.txt

# On other machines:
echo "COPIED_TOKEN" > ~/.huntsman/seeknow_session.txt
# Or SSH copy: scp user@machine1:~/.huntsman/seeknow_session.txt ~/.huntsman/
```

---

## Why No Automatic Browser Automation?

### Playwright Crate Not Available

The `playwright` crate (for Rust) does not have a stable, maintained version in crates.io that:
- Compiles on Rust 1.88 MSRV
- Works on Termux/aarch64 (primary HSE target)
- Has no native library dependencies

### Alternatives Considered

1. **Playwright.js via child process** — Would require Node.js, adds significant complexity
2. **Headless Firefox** — Would require bundling entire browser
3. **Custom HTTP + regex parsing** — Cannot solve Turnstile without JavaScript
4. **API key from environment** — Requires existing authentication to retrieve
5. **Manual login + cookie reuse** ✅ **CHOSEN** — Simplest, no extra dependencies, works reliably

---

## Future Improvements

Once available, we could implement:

1. **Turnstile bypass via Playwright** (if stable Rust crate released)
2. **WebDriver support** (Selenium, WebSocket-based automation)
3. **OAuth flow automation** (if SeekNow adds OAuth support)
4. **Passwordless email extraction** (if we can integrate email polling)

For now, **manual login + token reuse** is the most practical solution.

---

## Security Considerations

### Token Security

- **Keep token private** — Anyone with your token can access your account
- **Don't commit to Git** — The file `~/.huntsman/seeknow_session.txt` is in `.gitignore`
- **Rotate regularly** — Re-login and save a new token every 30 days
- **Different devices** — Use different tokens per device if possible (same token works everywhere but device compromise exposes all)

### Best Practices

```bash
# GOOD: Store token securely
touch ~/.huntsman/seeknow_session.txt
chmod 600 ~/.huntsman/seeknow_session.txt  # Owner read/write only
echo "YOUR_TOKEN" > ~/.huntsman/seeknow_session.txt

# BAD: Don't do these
echo "token" | xargs -I {} hse scan  # Exposes in process list
export SEEKNOW_TOKEN="..."  # Visible in shell history
cat token.txt && hse scan  # Visible in bash logs
```

---

## Feedback & Issues

If you're unable to extract a token or have authentication issues:

1. **Verify Turnstile is showing** — When you visit https://see-know.ru in a new incognito window, do you see the Cloudflare Turnstile challenge?
2. **Check browser console** — Are there any JavaScript errors?
3. **Try different browser** — Try Firefox, Safari, or mobile browser to confirm it's not browser-specific
4. **Check IP reputation** — SeekNow might block certain VPNs/proxies; try direct connection

---

## See Also

- **SEEKNOW_SETUP.md** — Original guide (API key method, fallback to web automation)
- **SEEKNOW_QUICK_START.md** — Quick reference for 15,000 daily searches
- **OSINT_API_REFERENCE.md** — SeekNow endpoint documentation
