//! Embedded API credentials for private/offline use.
//!
//! This module provides fallback API keys that are compiled directly into
//! the binary. These are used when environment variables are not set.
//!
//! ⚠️  SECURITY WARNING: This file contains live API credentials.
//! Only use for private repositories. NEVER commit this to public repositories.
//!
//! To add your API keys:
//! 1. Add entries to the `EMBEDDED_KEYS` hashmap below
//! 2. Use the format: "HUNTSMAN_SERVICE_KEY" => "your-api-key-here"
//! 3. Rebuild the project: cargo build --release

use std::collections::HashMap;
use std::sync::OnceLock;

static EMBEDDED_KEYS: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

/// Get the embedded credentials map.
pub fn get_embedded_keys() -> &'static HashMap<&'static str, &'static str> {
    EMBEDDED_KEYS.get_or_init(|| {
        #[allow(unused_mut)] // mut is needed when users uncomment insert() calls
        let mut keys = HashMap::new();

        // ════════════════════════════════════════════════════════════════════════════════════
        // THREAT INTELLIGENCE & MALWARE SCANNING
        // ════════════════════════════════════════════════════════════════════════════════════

        // VirusTotal — malware/phishing/infrastructure scanning
        // Signup: https://www.virustotal.com/gui/join-us
        // keys.insert("HUNTSMAN_VIRUSTOTAL_KEY", "your-virustotal-api-key");

        // GreyNoise — internet-wide noise classification
        // Signup: https://viz.greynoise.io/signup
        // keys.insert("HUNTSMAN_GREYNOISE_KEY", "your-greynoise-api-key");

        // URLScan.io — URL/domain sandbox scanning
        // Signup: https://urlscan.io/
        // keys.insert("HUNTSMAN_URLSCAN_KEY", "your-urlscan-api-key");

        // AbuseIPDB — IP abuse/reputation database
        // Signup: https://www.abuseipdb.com/register
        // keys.insert("HUNTSMAN_ABUSEIPDB_KEY", "your-abuseipdb-api-key");

        // ════════════════════════════════════════════════════════════════════════════════════
        // BREACH & INTELLIGENCE
        // ════════════════════════════════════════════════════════════════════════════════════

        // SeekNow — breach + stealer intelligence
        // Signup: https://see-know.eu/signup
        // keys.insert("HUNTSMAN_SEEKNOW_KEY", "seek-your-api-key-here");

        // Have I Been Pwned — personal breach search
        // Signup: https://haveibeenpwned.com/API/Key
        // keys.insert("HUNTSMAN_HIBP_KEY", "your-hibp-api-key");

        // Intelligence X — breach/dark-web search
        // Signup: https://intelx.io/
        // keys.insert("HUNTSMAN_INTELX_KEY", "your-intelx-api-key");

        // OathNet Pro — breach + stealer intelligence
        // Signup: https://oathnet.org
        // keys.insert("HUNTSMAN_OATHNET_KEY", "your-oathnet-bearer-token");

        // ════════════════════════════════════════════════════════════════════════════════════
        // INFRASTRUCTURE / IP / DOMAIN INTELLIGENCE
        // ════════════════════════════════════════════════════════════════════════════════════

        // Shodan — IP/domain/cert intelligence
        // Signup: https://www.shodan.io/
        // keys.insert("HUNTSMAN_SHODAN_KEY", "your-shodan-api-key");

        // SecurityTrails — historical DNS + domain intelligence
        // Signup: https://securitytrails.com/
        // keys.insert("HUNTSMAN_SECTRAILS_KEY", "your-securitytrails-api-key");

        // LeakIX — exposure/leak intelligence
        // Signup: https://leakix.net/
        // keys.insert("HUNTSMAN_LEAKIX_KEY", "your-leakix-api-key");

        // Criminal IP — cybercrime intelligence / IP reputation
        // Signup: https://www.criminalip.io/
        // keys.insert("HUNTSMAN_CRIMINALIP_KEY", "your-criminalip-api-key");

        // IPQualityScore — IP fraud/proxy/VPN detection
        // Signup: https://www.ipqualityscore.com/
        // keys.insert("HUNTSMAN_IPQS_KEY", "your-ipqs-api-key");

        // ════════════════════════════════════════════════════════════════════════════════════
        // IDENTITY / PERSON INTELLIGENCE
        // ════════════════════════════════════════════════════════════════════════════════════

        // Proxycurl — LinkedIn profile enrichment
        // Signup: https://nubela.co/proxycurl/
        // keys.insert("HUNTSMAN_PROXYCURL_KEY", "your-proxycurl-api-key");

        // Hunter.io — corporate email discovery
        // Signup: https://hunter.io/
        // keys.insert("HUNTSMAN_HUNTER_KEY", "your-hunter-io-key");

        // EmailRep — email reputation and validation
        // Signup: https://emailrep.io/
        // keys.insert("HUNTSMAN_EMAILREP_KEY", "your-emailrep-api-key");

        // GitHub Personal Access Token — GitHub profile/repo/code search
        // Signup: https://github.com/settings/tokens
        // keys.insert("HUNTSMAN_GITHUB_TOKEN", "ghp_your-github-token");

        // ════════════════════════════════════════════════════════════════════════════════════
        // GEOINT / LOCATION INTELLIGENCE
        // ════════════════════════════════════════════════════════════════════════════════════

        // WiGLE — Wi-Fi/cell tower geolocation (requires both USER and TOKEN)
        // Signup: https://wigle.net/
        // keys.insert("HUNTSMAN_WIGLE_USER", "your-wigle-username");
        // keys.insert("HUNTSMAN_WIGLE_TOKEN", "your-wigle-token");

        // ════════════════════════════════════════════════════════════════════════════════════
        // ADDITIONAL SERVICES
        // ════════════════════════════════════════════════════════════════════════════════════

        // Exa AI — neural semantic web search
        // Signup: https://exa.ai/
        // keys.insert("HUNTSMAN_EXA_KEY", "your-exa-ai-api-key");

        keys
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_keys_map_is_created() {
        let keys = get_embedded_keys();
        // Verify the map is created and accessible (it will be empty until keys are added)
        assert_eq!(keys.len(), 0);
    }
}
