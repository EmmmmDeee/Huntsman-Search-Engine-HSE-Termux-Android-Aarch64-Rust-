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

        // Abuse.ch ThreatFox — malware threat intelligence
        // Signup: https://threatfox.abuse.ch/api/
        // keys.insert("HUNTSMAN_THREATFOX_KEY", "your-threatfox-api-key");

        // Abuse.ch URLhaus — malicious URL database
        // No signup required for basic access
        // keys.insert("HUNTSMAN_ABUSECH_KEY", "your-abusech-api-key");

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

        // Stolen.tax — exposed password + data dumps
        // Signup: https://stolen.tax/
        // keys.insert("HUNTSMAN_STOLEN_TAX_KEY", "your-stolen-tax-api-key");

        // DeHashed — breach + stealer logs
        // Signup: https://www.dehashed.com/
        // keys.insert("HUNTSMAN_DEHASHED_KEY", "your-dehashed-api-key");

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

        // Censys — scan database + certificate intelligence (requires ID + SECRET)
        // Signup: https://censys.io/
        // keys.insert("HUNTSMAN_CENSYS_ID", "your-censys-id");
        // keys.insert("HUNTSMAN_CENSYS_SECRET", "your-censys-secret");

        // FOFA — China-based scan database + asset intelligence
        // Signup: https://fofa.info/
        // keys.insert("HUNTSMAN_FOFA_KEY", "your-fofa-api-key");

        // Netlas — scan database + infrastructure intelligence
        // Signup: https://netlas.io/
        // keys.insert("HUNTSMAN_NETLAS_KEY", "your-netlas-api-key");

        // Onyphe — internet exposure intelligence
        // Signup: https://www.onyphe.io/
        // keys.insert("HUNTSMAN_ONYPHE_KEY", "your-onyphe-api-key");

        // WHOIS-XML — domain + IP intelligence
        // Signup: https://whois.whoisxmlapi.com/
        // keys.insert("HUNTSMAN_WHOISXML_KEY", "your-whoisxml-api-key");

        // DomainsDB — domain intelligence + reverse DNS
        // Signup: https://domainsdb.info/
        // keys.insert("HUNTSMAN_DOMAINSDB_KEY", "your-domainsdb-api-key");

        // OSINTCat — infrastructure asset search
        // Signup: https://osintcat.com/
        // keys.insert("HUNTSMAN_OSINTCAT_KEY", "your-osintcat-api-key");

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

        // FullContact — person/company data enrichment
        // Signup: https://www.fullcontact.com/
        // keys.insert("HUNTSMAN_FULLCONTACT_KEY", "your-fullcontact-api-key");

        // SEON — email/phone/person intelligence
        // Signup: https://seon.io/
        // keys.insert("HUNTSMAN_SEON_KEY", "your-seon-api-key");

        // Trove — personal data intelligence + people search
        // Signup: https://trove.ai/
        // keys.insert("HUNTSMAN_TROVE_KEY", "your-trove-api-key");

        // ════════════════════════════════════════════════════════════════════════════════════
        // TELECOMMUNICATIONS & IDENTITY VERIFICATION
        // ════════════════════════════════════════════════════════════════════════════════════

        // NumVerify — phone number validation + carrier lookup
        // Signup: https://numverify.com/
        // keys.insert("HUNTSMAN_NUMVERIFY_KEY", "your-numverify-api-key");

        // OpenCNAM — reverse phone lookup (caller ID)
        // Signup: https://www.opencnam.com/
        // keys.insert("HUNTSMAN_OPENCNAM_KEY", "your-opencnam-api-key");

        // Epieos Tools — phone number OSINT
        // Signup: https://tools.epieos.com/
        // keys.insert("HUNTSMAN_EPIEOS_KEY", "your-epieos-api-key");

        // Niamonx — HLR lookup + mobile analytics
        // Signup: https://niamonx.io/
        // keys.insert("HUNTSMAN_NIAMONX_KEY", "your-niamonx-api-key");
        // keys.insert("HUNTSMAN_HLR_KEY", "your-hlr-api-key");

        // ════════════════════════════════════════════════════════════════════════════════════
        // GEOINT / LOCATION INTELLIGENCE
        // ════════════════════════════════════════════════════════════════════════════════════

        // WiGLE — Wi-Fi/cell/BT/geo geolocation database
        // Signup: https://wigle.net/
        // keys.insert("HUNTSMAN_WIGLE_USER", "your-wigle-username");
        // keys.insert("HUNTSMAN_WIGLE_TOKEN", "your-wigle-token");
        // keys.insert("HUNTSMAN_WIGLE_SSID_SCAN_CAP", "1000");
        // keys.insert("HUNTSMAN_WIGLE_SSID_SESSION_CAP", "10000");
        // keys.insert("HUNTSMAN_WIGLE_BSSID_SCAN_CAP", "1000");
        // keys.insert("HUNTSMAN_WIGLE_BSSID_SESSION_CAP", "10000");
        // keys.insert("HUNTSMAN_WIGLE_CELL_SCAN_CAP", "1000");
        // keys.insert("HUNTSMAN_WIGLE_CELL_SESSION_CAP", "10000");
        // keys.insert("HUNTSMAN_WIGLE_GEO_SCAN_CAP", "1000");
        // keys.insert("HUNTSMAN_WIGLE_GEO_SESSION_CAP", "10000");
        // keys.insert("HUNTSMAN_WIGLE_BT_SCAN_CAP", "1000");
        // keys.insert("HUNTSMAN_WIGLE_BT_SESSION_CAP", "10000");

        // OpenCellID — cellular geolocation database
        // Signup: https://opencellid.org/
        // keys.insert("HUNTSMAN_OPENCELLID_KEY", "your-opencellid-api-key");

        // ════════════════════════════════════════════════════════════════════════════════════
        // BUSINESS & CORPORATE INTELLIGENCE
        // ════════════════════════════════════════════════════════════════════════════════════

        // OpenCorporates — business registry + company intelligence
        // Signup: https://opencorporates.com/
        // keys.insert("HUNTSMAN_OPENCORP_KEY", "your-opencorp-api-key");

        // OpenSanctions — sanctions/enforcement database
        // Signup: https://www.opensanctions.org/
        // keys.insert("HUNTSMAN_OPENSANCTIONS_KEY", "your-opensanctions-api-key");

        // BuiltWith — technology intelligence + website profiling
        // Signup: https://builtwith.com/
        // keys.insert("HUNTSMAN_BUILTWITH_KEY", "your-builtwith-api-key");

        // ════════════════════════════════════════════════════════════════════════════════════
        // ENTERPRISE / INTERNAL CONFIGURATION
        // ════════════════════════════════════════════════════════════════════════════════════

        // ABN Lookup — Australian business register lookup (ABN GUID)
        // Signup: https://www.abn.gov.au/
        // keys.insert("HUNTSMAN_ABR_GUID", "your-abr-guid");

        // Huntsman internal proxy configuration for enterprise use
        // keys.insert("HUNTSMAN_SEARCH_PROXY", "http://proxy.example.com:8080");

        // Email domains list (semicolon-separated) for advanced filtering
        // keys.insert("HUNTSMAN_EMAIL_DOMAINS", "example.com;company.com");

        // Engine health check interval (seconds)
        // keys.insert("HUNTSMAN_ENGINE_HEALTH_SECS", "300");

        // SeekNow scan cap per-scan (default: unlimited)
        // keys.insert("HUNTSMAN_SEEKNOW_SCAN_CAP", "1000");

        // ════════════════════════════════════════════════════════════════════════════════════
        // ADDITIONAL SERVICES
        // ════════════════════════════════════════════════════════════════════════════════════

        // Exa AI — neural semantic web search
        // Signup: https://exa.ai/
        // keys.insert("HUNTSMAN_EXA_KEY", "your-exa-ai-api-key");

        // AlienVault OTX — open-source threat intelligence
        // Signup: https://otx.alienvault.com/
        // keys.insert("HUNTSMAN_ALIENVAULT_KEY", "your-alienvault-api-key");

        // ZoomEye — China-based internet-wide scan database
        // Signup: https://www.zoomeye.org/
        // keys.insert("HUNTSMAN_ZOOMEYE_KEY", "your-zoomeye-api-key");

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
