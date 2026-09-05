# HSE All-In-One Complete Setup (CLI + Web UI)

**Complete end-to-end setup guide for Huntsman Search Engine with SeekNow authentication fallback.**

---

## 📋 Prerequisites Checklist

- [ ] **Termux installed** (F-Droid or GitHub release; NOT Play Store)
- [ ] **Device has network access** (WiFi or mobile data)
- [ ] **Battery configured** (Settings → Termux → Battery → Unrestricted)
- [ ] **Background data enabled** (Android Settings → Termux → Allow background data)

---

## 🚀 Installation (One Line — Everything Included)

This single command installs HSE, pulls dependencies, builds the binary, and verifies everything:

```bash
curl -fsSL https://raw.githubusercontent.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-/main/install.sh | bash
```

**Re-run anytime to upgrade** — idempotent, preserves your keys. For exactly
what this does, the no-build prebuilt-binary fast path, private-repo auth,
environment knobs, and troubleshooting, see [`docs/INSTALL.md`](INSTALL.md)
— this guide picks up from there with the SeekNow/Web-UI setup
`INSTALL.md` doesn't cover.

---

## 🔐 Step 1: Configure SeekNow Authentication (API Key or Web Login)

### Option A: SeekNow API Key (Preferred — if you have one)

If you already have a SeekNow API key (`seek-...` format):

```bash
# Edit the config file
nano ~/.huntsman.env

# Add your key:
HUNTSMAN_SEEKNOW_KEY="seek-your-64-char-key-here"
```

**Verify it works:**
```bash
hse doctor
# Expected: "SeekNow: 5000 credits remaining" (or your daily limit)
```

### Option B: SeekNow Web Login + Session Reuse (No API Key Required)

> **⚠️ Not currently wired into a scan** — the code exists
> (`web_client_advanced.rs`/`web_dispatcher.rs`) but nothing in
> `src/modules/see_know/` calls it yet, so a saved session token below is
> not read by HSE today. Full detail: `docs/SEEKNOW_WEB_AUTOMATION.md`.

**Problem:** Cloudflare Turnstile blocks all HTTP-only login attempts.

**Solution:** Log in manually via browser, then save your session token for HSE to reuse.

#### Step 1: Manual browser login (one-time)
1. Open **Chrome/Firefox** on your device
2. Navigate to: **https://see-know.ru**
3. **Solve the Turnstile challenge** when it appears
4. **Log in** with your credentials

#### Step 2: Extract session token
After successful login, open **Chrome DevTools** (`F12`):

**Method 1: Cookies**
- Go to **Application** tab
- Expand **Cookies** in sidebar
- Click `https://see-know.ru`
- Look for cookie: `auth_token`, `session`, `token`, or anything starting with `seek-`
- **Copy the entire cookie value**

**Method 2: Local Storage**
- Go to **Application** → **Local Storage**
- Click `https://see-know.ru`
- Look for key: `auth_token` or `session_token`
- **Copy the value**

#### Step 3: Save token to HSE
```bash
# Create directory
mkdir -p ~/.huntsman

# Save token
echo "YOUR_TOKEN_HERE" > ~/.huntsman/seeknow_session.txt

# Verify
cat ~/.huntsman/seeknow_session.txt
```

**Saved — but see the warning above.** HSE does not yet load or reuse this
token for any search; `hse doctor` will still report SeekNow unavailable
until it's wired in. See `docs/SEEKNOW_WEB_AUTOMATION.md` for the current
state and what's blocking it. If you need SeekNow working today, use
Option A (API key) instead.

---

## 📊 Step 3: Launch HSE Web UI

### Start the web server

```bash
# Launch on loopback (127.0.0.1:8080)
hse serve
```

**Output should show:**
```
[INFO] HSE server listening on 127.0.0.1:8080 (loopback only)
[INFO] Press Ctrl+C to stop
```

### Access the Web UI

1. **Open Chrome/Firefox** on the phone
2. Navigate to: **`http://127.0.0.1:8080`**
3. You'll see the dashboard with tabs:
   - **Dashboard** — Summary of recent scans
   - **New Scan** — Launch a scan from the Web UI
   - **Scans** — Browse past scan results
   - **Live** — Real-time event log
   - **Engines** — Module health & capability probes
   - **Settings** — Save API keys, toggle features

---

## 🔍 Step 4: Run Your First Scan

### Via Web UI (Easiest)

1. Click **New Scan**
2. Enter a target (email, username, domain, IP, phone)
3. Click **Scan**
4. Watch results populate in real-time

### Via CLI

```bash
# Search an email
hse scan --kind email --value user@example.com

# Search a username
hse scan --kind username --value octocat

# Search a domain
hse scan --kind domain --value example.com
```

### Via API

```bash
# Start a scan
curl -X POST http://127.0.0.1:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"value": "test@example.com", "kind": "email"}'

# Get results
curl http://127.0.0.1:8080/api/v1/scans/latest

```

---

## 🔧 Advanced Configuration

### SeekNow Quota Management

Control how many credits per scan HSE can use:

```bash
# Limit to 50 credits per scan
hse scan --seeknow-scan-cap 50 --value user@example.com

# Or set globally
echo 'export HUNTSMAN_SEEKNOW_SCAN_CAP=250' >> ~/.huntsman.env
```

---

## 🐛 Troubleshooting

### "SeekNow: All authentication methods failed"

See `docs/SEEKNOW_WEB_AUTOMATION.md`'s Troubleshooting section ("All SeekNow
authentication methods failed") — same fix (re-login, re-extract the token,
re-save it to `~/.huntsman/seeknow_session.txt`), kept in one place.

### "Scanner timeout / slow results"

**Problem:** Network flaky or API provider slow.

**Solution:**
```bash
# Increase timeout
export HUNTSMAN_SEEKNOW_TIMEOUT=120  # seconds

# Check real-time progress
hse serve  # Watch Live tab for events
```

---

## 📈 Next Steps

1. **Run several scans** to populate history and test results
2. **Explore advanced modules** — `hse modules` lists all 188 available modules
3. **Set up CI/automation** — webhook integrations, scheduled scans, etc.
4. **Share scans** — Export to JSON/CSV from Web UI or API

---

## 🔗 Additional Resources

- **SeekNow integration:** `docs/SEEKNOW_SETUP.md`
- **Turnstile workaround:** `docs/SEEKNOW_WEB_AUTOMATION.md`
- **Credential & session hygiene:** `docs/ADVANCED_TECHNIQUES.md`
- **Architecture details:** README.md → Architecture section

---

## 💬 Support

**Common issues:** Run `hse doctor` — it diagnoses most setup problems.

**Full diagnostic bundle:** Settings → Diagnostics → Download (in Web UI).

**Health check:** `hse selftest`, or `hse doctor --live` for a live provider probe.
