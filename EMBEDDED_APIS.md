# Embedded API Keys for Private Use

This document explains how to configure embedded API keys directly in the Huntsman Search Engine for private/offline use.

## Overview

For private use of the Huntsman Search Engine, you can embed live API credentials directly into the compiled binary. This eliminates the need for external configuration files and allows the tool to function in isolated environments.

**⚠️  Security Warning:** Embedded API keys should NEVER be committed to public repositories. This approach is ONLY suitable for private, self-hosted use.

## How It Works

1. **Environment Variables (Priority 1):** If `HUNTSMAN_*` environment variables are set, they are used.
2. **Embedded Credentials (Priority 2):** If environment variables are not set, the code falls back to embedded credentials.
3. **Error:** If neither are available, the module requires the key and reports an error.

This allows you to:
- Use environment variables in production/CI environments
- Use embedded keys for private/offline development
- Override embedded keys with environment variables when needed

## Configuration

### Step 1: Add Your API Keys

Edit `/src/util/keys/embedded_credentials.rs` and uncomment/add your API keys:

```rust
// Example: Add your VirusTotal key
keys.insert("HUNTSMAN_VIRUSTOTAL_KEY", "your-actual-virustotal-api-key-here");

// Example: Add your Shodan key
keys.insert("HUNTSMAN_SHODAN_KEY", "your-actual-shodan-api-key-here");

// Example: Add your GitHub token
keys.insert("HUNTSMAN_GITHUB_TOKEN", "ghp_your-actual-github-token-here");
```

### Step 2: Rebuild the Project

```bash
cargo build --release
```

### Step 3: Run Huntsman

The embedded keys will automatically be used:

```bash
hse scan --kind email --value test@example.com
```

## Supported APIs

The embedded credentials system supports all 70+ APIs used by Huntsman, including:

### Threat Intelligence
- VirusTotal
- GreyNoise
- URLScan
- AbuseIPDB

### Breach Intelligence
- SeekNow
- Have I Been Pwned (HIBP)
- Intelligence X
- OathNet Pro
- Stolen.tax
- DeHashed

### Infrastructure & IP Intelligence
- Shodan
- SecurityTrails
- LeakIX
- Criminal IP
- IPQualityScore

### Identity & People
- Proxycurl (LinkedIn)
- Hunter.io
- EmailRep
- GitHub

### Location Intelligence
- WiGLE (WiFi geolocation)
- OpenCellID

### And many more...

## Signup Links

For free API keys, visit:
- **VirusTotal:** https://www.virustotal.com/gui/join-us
- **Shodan:** https://account.shodan.io/register
- **SecurityTrails:** https://securitytrails.com/app/signup
- **Greynoise:** https://viz.greynoise.io/signup
- **AbuseIPDB:** https://www.abuseipdb.com/register
- **URLScan:** https://urlscan.io/user/signup
- **LeakIX:** https://leakix.net/auth/register
- **Hunter.io:** https://hunter.io/users/sign_up
- **GitHub:** https://github.com/settings/tokens (personal access tokens)

For paid services:
- **Proxycurl:** https://nubela.co/proxycurl/pricing
- **Shodan (Advanced):** https://www.shodan.io/pricing
- **SeekNow:** https://see-know.eu
- **HIBP:** https://haveibeenpwned.com/API/Key

## All Available Keys

The embedded credentials module supports the following environment variables:

```
# Threat Intelligence & Malware Scanning
HUNTSMAN_VIRUSTOTAL_KEY
HUNTSMAN_GREYNOISE_KEY
HUNTSMAN_URLSCAN_KEY
HUNTSMAN_ABUSEIPDB_KEY

# Breach & Intelligence
HUNTSMAN_SEEKNOW_KEY
HUNTSMAN_HIBP_KEY
HUNTSMAN_INTELX_KEY
HUNTSMAN_OATHNET_KEY
HUNTSMAN_STOLEN_TAX_KEY
HUNTSMAN_DEHASHED_KEY

# Infrastructure / IP / Domain Intelligence
HUNTSMAN_SHODAN_KEY
HUNTSMAN_SECTRAILS_KEY
HUNTSMAN_LEAKIX_KEY
HUNTSMAN_CRIMINALIP_KEY
HUNTSMAN_IPQS_KEY

# Identity / Person Intelligence
HUNTSMAN_PROXYCURL_KEY
HUNTSMAN_HUNTER_KEY
HUNTSMAN_EMAILREP_KEY
HUNTSMAN_GITHUB_TOKEN

# Geolocation / Location Intelligence
HUNTSMAN_WIGLE_USER
HUNTSMAN_WIGLE_TOKEN

# Additional Services
HUNTSMAN_EXA_KEY

# And more... (see embedded_credentials.rs for complete list)
```

## Environment Variable Override

Even with embedded keys, you can override them with environment variables:

```bash
# This will use the embedded key for most APIs
hse scan --kind email --value test@example.com

# This will override the embedded VirusTotal key with the environment variable
export HUNTSMAN_VIRUSTOTAL_KEY="your-override-key"
hse scan --kind domain --value example.com
```

## Best Practices

1. **Private Repository Only:** Only embed keys in private repositories
2. **Rotate Compromised Keys:** If you ever accidentally commit this to a public repo:
   - Revoke all embedded keys immediately at their respective providers
   - Create new keys
   - Update the embedded credentials
   - Force-push to override the public commit (with caution)

3. **Use .gitignore:** If you're developing locally, add this to `.gitignore` to prevent accidental commits:
   ```
   src/util/keys/embedded_credentials.rs
   ```

4. **CI/CD:** In CI/CD pipelines, use environment variables instead of embedded keys:
   ```yaml
   env:
     HUNTSMAN_VIRUSTOTAL_KEY: ${{ secrets.VIRUSTOTAL_KEY }}
     HUNTSMAN_SHODAN_KEY: ${{ secrets.SHODAN_KEY }}
   ```

## Troubleshooting

### Keys Not Being Used
- Verify keys are uncommented in `src/util/keys/embedded_credentials.rs`
- Rebuild the project: `cargo build --release`
- Check that environment variables aren't overriding them

### Module Reports "Key Required"
- The key may not be inserted into the map (check for typos)
- The key value may be empty or just a placeholder
- Verify the key name matches exactly (e.g., `HUNTSMAN_VIRUSTOTAL_KEY`, not `HUNTSMAN_VT_KEY`)

### Compilation Errors
- Ensure the key format in the HashMap is correct
- Keys should be valid API keys from their respective services
- Check for syntax errors in the Rust code

## Performance Impact

Embedded keys have NO performance impact. They are compiled into the binary at build time and retrieved at runtime with constant O(1) lookup.

## Security Considerations

- Embedded credentials are baked into the compiled binary
- Binaries containing real API keys should be treated as sensitive
- Do not distribute binaries with embedded production keys
- Consider using separate "read-only" or "dev" API keys
- Regularly audit which keys are embedded

## Updating Keys

To update an embedded key:

1. Edit `src/util/keys/embedded_credentials.rs`
2. Change the value for the key
3. Rebuild: `cargo build --release`
4. The new key will be used on next run

## Removing Keys

To disable an embedded key, simply comment it out:

```rust
// keys.insert("HUNTSMAN_VIRUSTOTAL_KEY", "...");
```

The system will then require the environment variable if the module is used.

## See Also

- `.env.example` - Template for environment variable configuration
- `src/util/keys/constants.rs` - Key registry and resolution logic
- `src/core/module/mod.rs` - Module context and key fetching
