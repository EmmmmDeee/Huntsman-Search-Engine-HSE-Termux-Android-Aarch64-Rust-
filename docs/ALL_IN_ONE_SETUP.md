# HSE All-In-One Complete Setup (CLI + Web UI + Ollama AI Analysis)

**Complete end-to-end setup guide for Huntsman Search Engine with SeekNow authentication fallback and Ollama integration.**

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
— this guide picks up from there with the SeekNow/Ollama/Web-UI setup
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

## 🤖 Step 2: Install & Configure Ollama (Optional but Recommended)

Ollama provides AI-powered analysis of scan results. **Completely optional** — HSE works fine without it.

### Install Ollama

**Linux/Termux (if sufficient storage available):**
```bash
# Download and install
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve   # Runs on http://127.0.0.1:11434
```

**macOS:**
```bash
# Via Homebrew or direct download from https://ollama.ai
brew install ollama
ollama serve
```

**Docker (if available):**
```bash
docker run -d -p 11434:11434 --name ollama ollama/ollama
docker exec ollama ollama pull qwen2.5:7b
```

### Pull a model

Keep Ollama running, then in another terminal:

```bash
# Pull a lightweight model (2-3 GB)
ollama pull qwen2.5:7b

# Verify it's ready
ollama list
# Expected: qwen2.5:7b [size]   [quantization]
```

### Enable AI analysis in HSE

```bash
# Arm the feature
hse config feature.ai_daemon on

# Verify
hse doctor
# Expected: "AI-Daemon: armed, model qwen2.5:7b available"
```

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
5. When done, click **Analyze** (if Ollama is running) for AI summary

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

# Analyze with Ollama
curl -X POST http://127.0.0.1:8080/api/v1/scans/latest/analyze \
  -H "Content-Type: application/json" \
  -d '{"model": "qwen2.5:7b"}'
```

---

## 🔧 Advanced Configuration

### SeekNow Quota Management

Control how many credits per scan HSE can use:

```bash
# Limit to 50 credits per scan
hse scan --seeknow-scan-cap 50 user@example.com

# Or set globally
echo 'export HUNTSMAN_SEEKNOW_SCAN_CAP=250' >> ~/.huntsman.env
```

### Ollama Model Selection

Use different models for different analysis:

```bash
# Use a larger, more accurate model (if you have storage/RAM)
ollama pull mistral:7b

# Analyze with Mistral instead
hse analyze --scan-id latest --model mistral:7b

# Or set for daemon
export HUNTSMAN_OLLAMA_MODEL=mistral:7b
hse-ai-daemon
```

**Recommended models:**
- `qwen2.5:7b` — Lightweight, fast, good for mobile (default)
- `mistral:7b` — Better reasoning, moderate size
- `llama2:7b` — Alternative lightweight model
- `neural-chat:7b` — Tuned for chat/analysis

### Background AI Analysis (Termux)

Keep Ollama running in the background:

```bash
# Install termux-services
pkg install termux-services

# Create service directory
mkdir -p $PREFIX/var/service/ollama

# Create run script
cat > $PREFIX/var/service/ollama/run <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
exec ollama serve
EOF

chmod +x $PREFIX/var/service/ollama/run

# Enable and start
sv-enable ollama
sv up ollama

# Check status
sv status ollama
```

Similarly for the HSE AI daemon — see the README's
["Running `hse-ai-daemon` persistently (Termux)"](../README.md#running-hse-ai-daemon-persistently-termux)
for the same `termux-services` setup plus what `sv-enable`/`sv down`/`sv up`
do once it's running.

---

## 🐛 Troubleshooting

### "SeekNow: All authentication methods failed"

See `docs/SEEKNOW_WEB_AUTOMATION.md`'s Troubleshooting section ("All SeekNow
authentication methods failed") — same fix (re-login, re-extract the token,
re-save it to `~/.huntsman/seeknow_session.txt`), kept in one place.

### "Ollama connection refused"

**Problem:** Ollama not running or wrong URL.

**Solution:**
```bash
# Verify Ollama is running
curl http://127.0.0.1:11434/api/tags
# Should return JSON list of models

# Check environment variable
echo $HUNTSMAN_OLLAMA_URL
# Should be http://127.0.0.1:11434 (default)

# If running on different host/port
export HUNTSMAN_OLLAMA_URL=http://192.168.1.100:11434
hse-ai-daemon
```

### "Model not found"

**Problem:** Model pulled to Ollama, but HSE can't find it.

**Solution:**
```bash
# List available models
ollama list

# Pull if missing
ollama pull qwen2.5:7b

# Specify exact model name
export HUNTSMAN_OLLAMA_MODEL=qwen2.5:7b
hse analyze --scan-id latest
```

### "Scanner timeout / slow results"

**Problem:** Network flaky or API provider slow.

**Solution:**
```bash
# Increase timeout
export HUNTSMAN_SEEKNOW_TIMEOUT=120  # seconds

# Run in dry-run mode first
hse scan --dry-run user@example.com

# Check real-time progress
hse serve  # Watch Live tab for events
```

---

## 📈 Next Steps

1. **Run several scans** to populate history and test results
2. **Fine-tune Ollama model** for your analysis needs — see `docs/OSINT_MODEL_FINE_TUNING.md`
3. **Explore advanced modules** — `hse selftest` shows all 175 available modules
4. **Set up CI/automation** — webhook integrations, scheduled scans, etc.
5. **Share scans** — Export to JSON/CSV from Web UI or API

---

## 🔗 Additional Resources

- **SeekNow integration:** `docs/SEEKNOW_SETUP.md`
- **Turnstile workaround:** `docs/SEEKNOW_WEB_AUTOMATION.md`
- **Ollama fine-tuning:** `docs/OSINT_MODEL_FINE_TUNING.md`
- **Credential & session hygiene:** `docs/ADVANCED_TECHNIQUES.md`
- **Architecture details:** README.md → Architecture section

---

## 💬 Support

**Common issues:** Run `hse doctor` — it diagnoses most setup problems.

**Full diagnostic bundle:** Settings → Diagnostics → Download (in Web UI).

**Health check:** `hse selftest` or `hse live-capability-probe`.
