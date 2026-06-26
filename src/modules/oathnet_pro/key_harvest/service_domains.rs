//! API-domain → service-tag lookup for stealer/breach record routing.
//!
//! Extracted from `key_harvest::mod.rs` so the lookup table doesn't
//! dominate the file. Used by `store_api_credential` to tag a record
//! when the URL field carries a known provider domain.

pub(super) const API_SERVICE_DOMAINS: &[(&str, &str)] = &[
    // ── Self-discovery: finding more OathNet keys scales our own quota ──
    ("oathnet.org", "oathnet"),
    ("oathnet.com", "oathnet"),
    ("api.oathnet.org", "oathnet"),
    ("dashboard.oathnet.org", "oathnet"),
    ("docs.oathnet.org", "oathnet"),
    // ── OathNet competitors (same data, parallel quota pools) ───────────
    ("see-know.eu", "see_know"),
    ("api.see-know.eu", "see_know"),
    ("app.see-know.eu", "see_know"),
    ("dashboard.see-know.eu", "see_know"),
    ("snusbase.com", "snusbase"),
    ("api.snusbase.com", "snusbase"),
    ("leakcheck.io", "leakcheck"),
    ("leakcheck.net", "leakcheck"),
    ("api.leakcheck.net", "leakcheck"),
    ("leakpeek.com", "leakpeek"),
    ("leak-lookup.com", "leak_lookup"),
    ("api.leak-lookup.com", "leak_lookup"),
    ("hashes.com", "hashes"),
    ("psbdmp.ws", "psbdmp"),
    ("ghostproject.fr", "ghostproject"),
    ("scylla.so", "scylla"),
    ("scylla.sh", "scylla"),
    ("weleakinfo.to", "weleakinfo"),
    ("weleakinfo.com", "weleakinfo"),
    ("hackcheck.io", "hackcheck"),
    ("api.hackcheck.io", "hackcheck"),
    ("scrubd.com", "scrubd"),
    ("nuclearleaks.com", "nuclearleaks"),
    ("breachforums.is", "breachforums"),
    ("breachforums.st", "breachforums"),
    ("inteltechniques.com", "inteltechniques"),
    // ── Existing entries ────────────────────────────────────────────────
    ("shodan.io", "shodan"),
    ("account.shodan.io", "shodan"),
    ("virustotal.com", "virustotal"),
    ("hunter.io", "hunter"),
    ("securitytrails.com", "securitytrails"),
    ("dehashed.com", "dehashed"),
    ("app.dehashed.com", "dehashed"),
    ("api.dehashed.com", "dehashed"),
    ("intelx.io", "intelx"),
    ("2.intelx.io", "intelx"),
    ("free.intelx.io", "intelx"),
    ("numverify.com", "numverify"),
    ("wigle.net", "wigle"),
    ("ipqualityscore.com", "ipqs"),
    ("leakix.net", "leakix"),
    ("haveibeenpwned.com", "hibp"),
    ("censys.io", "censys"),
    ("search.censys.io", "censys"),
    ("binaryedge.io", "binaryedge"),
    ("app.binaryedge.io", "binaryedge"),
    ("greynoise.io", "greynoise"),
    ("viz.greynoise.io", "greynoise"),
    ("fullhunt.io", "fullhunt"),
    ("urlscan.io", "urlscan"),
    ("abuseipdb.com", "abuseipdb"),
    ("serpapi.com", "serpapi"),
    ("criminalip.io", "criminal_ip"),
    ("api.criminalip.io", "criminal_ip"),
    ("abuse.ch", "threatfox"),
    ("openai.com", "openai"),
    ("api.openai.com", "openai"),
    ("anthropic.com", "anthropic"),
    ("api.anthropic.com", "anthropic"),
    ("passivetotal.org", "passivetotal"),
    // `riskiq.net` is RiskIQ's own brand domain → it maps to `riskiq` in the
    // RiskIQ cluster below; it must NOT also live here, or (first-match-wins)
    // every riskiq.net URL would tag as `passivetotal` and the `riskiq` entry
    // would be dead. PassiveTotal is still detected via `passivetotal.org`.
    ("onyphe.io", "onyphe"),
    ("zoomeye.org", "zoomeye"),
    ("api.zoomeye.org", "zoomeye"),
    ("fofa.info", "fofa"),
    ("en.fofa.info", "fofa"),
    ("netlas.io", "netlas"),
    ("app.netlas.io", "netlas"),
    ("pulsedive.com", "pulsedive"),
    ("builtwith.com", "builtwith"),
    ("emailrep.io", "emailrep"),
    ("seon.io", "seon"),
    ("api.seon.io", "seon"),
    ("epieos.com", "epieos"),
    ("api.epieos.com", "epieos"),
    ("nubela.co", "proxycurl"),
    ("opencorporates.com", "opencorporates"),
    ("api.opencorporates.com", "opencorporates"),
    ("whoisxmlapi.com", "whoisxml"),
    ("breachdirectory.org", "breachdirectory"),
    ("c99.nl", "c99"),
    ("api.c99.nl", "c99"),
    ("twilio.com", "twilio"),
    ("console.twilio.com", "twilio"),
    ("app.snyk.io", "snyk"),
    ("snyk.io", "snyk"),
    ("cloud.digitalocean.com", "digitalocean"),
    ("digitalocean.com", "digitalocean"),
    ("ngrok.com", "ngrok"),
    ("dashboard.ngrok.com", "ngrok"),
    ("mailchimp.com", "mailchimp"),
    ("app.mailchimp.com", "mailchimp"),
    ("discord.com", "discord"),
    ("discordapp.com", "discord"),
    ("registry.npmjs.org", "npm"),
    ("pypi.org", "pypi"),
    ("vercel.com", "vercel"),
    ("app.netlify.com", "netlify"),
    ("heroku.com", "heroku"),
    ("dashboard.heroku.com", "heroku"),
    // AI / ML platforms
    ("openrouter.ai", "openrouter"),
    ("console.groq.com", "groq"),
    ("groq.com", "groq"),
    ("cohere.ai", "cohere"),
    ("dashboard.cohere.ai", "cohere"),
    ("mistral.ai", "mistral"),
    ("console.mistral.ai", "mistral"),
    ("together.ai", "together_ai"),
    ("api.together.xyz", "together_ai"),
    ("fal.ai", "fal_ai"),
    ("wandb.ai", "wandb"),
    ("app.wandb.ai", "wandb"),
    ("huggingface.co", "huggingface"),
    ("replicate.com", "replicate"),
    ("lightning.ai", "lightning_ai"),
    ("perplexity.ai", "perplexity"),
    // Cloud / hosting
    ("railway.app", "railway"),
    ("render.com", "render"),
    ("dashboard.render.com", "render"),
    ("supabase.com", "supabase"),
    ("app.supabase.com", "supabase"),
    ("clerk.com", "clerk"),
    ("dashboard.clerk.com", "clerk"),
    ("posthog.com", "posthog"),
    ("app.posthog.com", "posthog"),
    ("flagsmith.com", "flagsmith"),
    ("resend.com", "resend"),
    // Security / OSINT
    ("greynoise.io", "greynoise"),
    ("viz.greynoise.io", "greynoise"),
    ("gitlab.com", "gitlab"),
    ("riskiq.net", "riskiq"),
    ("community.riskiq.com", "riskiq"),
    ("spyse.com", "spyse"),
    ("securitytrails.com", "securitytrails"),
    ("app.securitytrails.com", "securitytrails"),
    // Mapping
    ("mapbox.com", "mapbox"),
    ("account.mapbox.com", "mapbox"),
    ("geocodio.io", "geocodio"),
    // Payment
    ("paystack.com", "paystack"),
    ("dashboard.paystack.com", "paystack"),
    ("razorpay.com", "razorpay"),
    ("dashboard.razorpay.com", "razorpay"),
    // Communication
    ("postmarkapp.com", "postmark"),
    ("account.postmarkapp.com", "postmark"),
    ("mailersend.com", "mailersend"),
    ("app.mailersend.com", "mailersend"),
    // Database
    ("cloud.mongodb.com", "mongodb_atlas"),
    ("atlas.mongodb.com", "mongodb_atlas"),
    ("neon.tech", "neon"),
    ("console.neon.tech", "neon"),
    ("planetscale.com", "planetscale"),
    ("app.planetscale.com", "planetscale"),
    ("upstash.com", "upstash"),
    ("console.upstash.com", "upstash"),
    // OSINT / validation (complete coverage)
    ("opencellid.org", "opencellid"),
    ("unwiredlabs.com", "opencellid"),
    // ── OSINT-practitioner tooling (expanded catalogue) ─────────────────────
    // A key for any of these found on a victim flags them as an OSINT operator;
    // every service tag here is classified in `osint_catalogue`. Domains are the
    // most reliable signal in stealer logs (which carry the URL the key was used
    // against). Real provider domains only — a wrong length/domain is a safe miss.
    // Breach / leak:
    ("hudsonrock.com", "hudsonrock"),
    ("cavalier.hudsonrock.com", "hudsonrock"),
    ("scatteredsecrets.com", "scatteredsecrets"),
    ("xposedornot.com", "xposedornot"),
    ("api.xposedornot.com", "xposedornot"),
    ("proxynova.com", "proxynova"),
    ("leakbase.io", "leakbase"),
    // Attack-surface scanners:
    ("hunter.how", "hunter_how"),
    ("quake.360.net", "quake"),
    // Threat intel:
    ("otx.alienvault.com", "alienvault_otx"),
    ("hybrid-analysis.com", "hybrid_analysis"),
    ("maltiverse.com", "maltiverse"),
    ("polyswarm.network", "polyswarm"),
    ("polyswarm.io", "polyswarm"),
    ("threatminer.org", "threatminer"),
    ("any.run", "anyrun"),
    ("app.any.run", "anyrun"),
    ("exchange.xforce.ibmcloud.com", "xforce"),
    // Email / people search:
    ("snov.io", "snov"),
    ("app.snov.io", "snov"),
    ("apollo.io", "apollo"),
    ("app.apollo.io", "apollo"),
    ("rocketreach.co", "rocketreach"),
    ("pipl.com", "pipl"),
    ("tomba.io", "tomba"),
    ("clearbit.com", "clearbit"),
    ("fullcontact.com", "fullcontact"),
    ("peopledatalabs.com", "peopledatalabs"),
    ("dropcontact.com", "dropcontact"),
    ("anymailfinder.com", "anymailfinder"),
    ("voilanorbert.com", "voilanorbert"),
    ("predictasearch.com", "predictasearch"),
    ("osint.industries", "osint_industries"),
    ("skymem.info", "skymem"),
    // Phone intelligence:
    ("numlookupapi.com", "numlookup"),
    ("veriphone.io", "veriphone"),
    ("hlr-lookups.com", "hlr_lookups"),
    ("abstractapi.com", "abstractapi_phone"),
    // IP geolocation:
    ("ipinfo.io", "ipinfo"),
    ("ip2location.com", "ip2location"),
    ("ip2location.io", "ip2location"),
    ("ipgeolocation.io", "ipgeolocation"),
    ("ipstack.com", "ipstack"),
    ("ipdata.co", "ipdata"),
    ("ipregistry.co", "ipregistry"),
    ("maxmind.com", "maxmind"),
    ("ipquery.io", "ipquery"),
    // Search / SERP / scraping recon:
    ("serper.dev", "serper"),
    ("zenserp.com", "zenserp"),
    ("exa.ai", "exa"),
    ("search.brave.com", "brave_search"),
    ("api.search.brave.com", "brave_search"),
    ("dataforseo.com", "dataforseo"),
    ("scraperapi.com", "scraperapi"),
    ("scrapingbee.com", "scrapingbee"),
    // Domain / WHOIS / DNS / cert:
    ("whoxy.com", "whoxy"),
    ("domaintools.com", "domaintools"),
    ("ip2whois.com", "ip2whois"),
    ("viewdns.info", "viewdns"),
    ("dnsdumpster.com", "dnsdumpster"),
    // Social / username link-analysis:
    ("sociallinks.io", "sociallinks"),
    ("maltego.com", "maltego"),
    ("lampyre.io", "lampyre"),
    ("spiderfoot.net", "spiderfoot"),
    ("hx.spiderfoot.net", "spiderfoot"),
];

pub(super) fn identify_service_from_url(url: &str) -> &'static str {
    let lower = url.to_lowercase();
    for (domain, service) in API_SERVICE_DOMAINS {
        if host_label_match(&lower, domain) {
            return service;
        }
    }
    "unknown"
}

/// True if `domain` occurs in `haystack` as a whole host — or as the suffix of
/// one, i.e. a subdomain of it — rather than as a fragment inside a longer label.
///
/// The caller feeds this messy breach-record URL fields (often no scheme, port,
/// or path), so the test stays substring-based for tolerance but requires
/// host-label boundaries on both sides of the match:
///   * **left** — start of string, or any char that can't continue a label
///     (not `[A-Za-z0-9-]`). A `.` qualifies, so `api.snusbase.com` still
///     matches `snusbase.com`, but `passwordhashes.com` does **not** match
///     `hashes.com`.
///   * **right** — end of string, or any char that can't continue a host (not
///     `[A-Za-z0-9-]` and not `.`). So `hashes.community` and `snusbase.com.au`
///     do **not** match `hashes.com` / `snusbase.com`, while `snusbase.com/path`
///     and `snusbase.com:8080` still do.
fn host_label_match(haystack: &str, domain: &str) -> bool {
    let h = haystack.as_bytes();
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(domain) {
        let at = from + rel;
        let end = at + domain.len();
        let left_ok = at == 0 || {
            let p = h[at - 1];
            !(p.is_ascii_alphanumeric() || p == b'-')
        };
        let right_ok = end == h.len() || {
            let n = h[end];
            !(n.is_ascii_alphanumeric() || n == b'-' || n == b'.')
        };
        if left_ok && right_ok {
            return true;
        }
        from = at + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_host() {
        assert!(host_label_match("example.com", "example.com"));
    }

    #[test]
    fn matches_subdomain_on_dot_boundary() {
        // `.` is not a label-continuation char, so the left boundary holds.
        assert!(host_label_match("api.example.com", "example.com"));
        assert!(host_label_match("dashboard.api.example.com", "example.com"));
    }

    #[test]
    fn rejects_left_substring_without_boundary() {
        // Preceding `t` is `[A-Za-z0-9-]`, so this is a fragment inside a longer
        // label, not a host-label match.
        assert!(!host_label_match("notexample.com", "example.com"));
        // A hyphen also continues a label on the left.
        assert!(!host_label_match("my-example.com", "example.com"));
    }

    #[test]
    fn rejects_right_extension_without_boundary() {
        // Trailing char after the match continues the host: alnum (`munity`)
        // or `.` (`.com.au`) both void the right boundary.
        assert!(!host_label_match("example.community", "example.com"));
        assert!(!host_label_match("example.com.au", "example.com"));
    }

    #[test]
    fn allows_trailing_port_path_or_separator() {
        // Right boundary is satisfied by any char that can't continue a host
        // (not `[A-Za-z0-9-.]`): `:`, `/`, whitespace.
        assert!(host_label_match("example.com:8080", "example.com"));
        assert!(host_label_match("example.com/path?key=v", "example.com"));
        assert!(host_label_match("https://example.com", "example.com"));
    }

    #[test]
    fn match_is_byte_exact_and_case_sensitive() {
        // `host_label_match` does no case folding (the public entry point
        // lowercases the haystack before calling it), so a mismatched case
        // simply fails the substring `find`.
        assert!(!host_label_match("EXAMPLE.COM", "example.com"));
        assert!(host_label_match("example.com", "example.com"));
        // A domain absent from the haystack never matches.
        assert!(!host_label_match("other.org", "example.com"));
    }
}
