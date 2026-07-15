//! Exposure-focused dork queries — API keys, credentials, cloud storage,
//! code repository leaks. These supplement `build_queries_base` with a
//! separate pass targeting unintentional data exposure rather than identity
//! discovery.

use crate::core::scan::{Target, TargetKind};

/// Build exposure-focused supplementary dork queries for a target.
///
/// These target secrets leaking via code repos, cloud storage, paste sites,
/// and misconfigured servers. Returns an empty Vec for target kinds where
/// exposure dorking doesn't add signal beyond `build_queries_base` (`Url`,
/// `Asn`, `Cidr`, `Coordinates`, `AbnAcn`, `MacAddress`, `ApiKey`,
/// `CryptoAddress` — `CryptoAddress`'s own base arm already bakes in
/// scam/abuse/fraud/attribution dorks, unlike `Address` below — `DeviceId`,
/// `Ssid`, `TrackingId`).
pub(super) fn build_queries_exposure(target: &Target) -> Vec<String> {
    let v = target.value.trim();
    if v.is_empty() {
        return Vec::new();
    }
    match target.kind {
        TargetKind::Domain => domain_exposure(v),
        TargetKind::Email => email_exposure(v),
        TargetKind::Username => username_exposure(v),
        TargetKind::Organisation => org_exposure(v),
        TargetKind::IpAddress => ip_exposure(v),
        TargetKind::Phone => phone_exposure(v),
        TargetKind::FullName => fullname_exposure(v),
        TargetKind::Address => address_exposure(v),
        _ => Vec::new(),
    }
}

fn domain_exposure(v: &str) -> Vec<String> {
    vec![
        // Exposed environment files
        format!("site:github.com \"{v}\" inurl:.env OR inurl:.env.production OR inurl:.env.local"),
        format!(
            "site:github.com \"{v}\" inurl:wp-config.php OR inurl:config.php OR inurl:settings.py"
        ),
        // AWS/cloud credentials
        format!("site:github.com \"{v}\" inurl:credentials OR inurl:aws.config"),
        format!("site:s3.amazonaws.com \"{v}\""),
        format!("site:storage.googleapis.com \"{v}\""),
        format!("site:blob.core.windows.net \"{v}\""),
        // Database dumps
        format!("site:github.com \"{v}\" ext:sql OR ext:dump"),
        format!("\"{v}\" filetype:sql intext:INSERT INTO"),
        // Exposed git repos
        format!("inurl:\"/.git/config\" site:{v}"),
        format!("intitle:\"index of\" \".git\" site:{v}"),
        // API keys in code repos
        format!("site:github.com \"{v}\" \"api_key\" OR \"secret_key\" OR \"access_token\""),
        format!("site:gitlab.com \"{v}\" \"PRIVATE_KEY\" OR \"SECRET\" OR \"PASSWORD\""),
        // Pastebin/code dump leaks
        format!("\"{v}\" site:pastebin.com password OR credentials OR api_key"),
        format!("\"{v}\" site:gist.github.com secret OR password OR key"),
        // Backup files
        format!("site:{v} inurl:backup OR inurl:archive filetype:zip OR filetype:tar"),
        // Error messages exposing internals
        format!("site:{v} intext:\"Fatal error\" OR intext:\"Stack trace\" OR intext:\"Warning:\""),
        // Exposed admin panels
        format!("site:{v} inurl:phpmyadmin OR inurl:adminer OR inurl:\"/_cpanel\""),
        // Docker/K8s
        format!("site:github.com \"{v}\" inurl:docker-compose.yml OR inurl:Dockerfile"),
    ]
}

fn email_exposure(v: &str) -> Vec<String> {
    let local = v.split('@').next().unwrap_or("");
    let mut q = vec![
        // Code repos with this email
        format!("site:github.com \"{v}\""),
        format!("site:gitlab.com \"{v}\""),
        // Credential dumps
        format!("\"{v}\" site:pastebin.com password OR hash OR md5"),
        format!("\"{v}\" site:ghostbin.co OR site:justpaste.it credentials"),
        // Cloud storage exposure
        format!("site:s3.amazonaws.com \"{v}\""),
        // Dark web indexers
        format!("\"{v}\" site:dehashed.com OR site:leakcheck.io OR site:snusbase.com"),
    ];
    if local.len() >= 3 {
        q.push(format!("site:github.com \"{local}\" email OR contact"));
        q.push(format!("\"{local}\" site:gist.github.com password OR key"));
    }
    q
}

fn username_exposure(v: &str) -> Vec<String> {
    vec![
        // Git commits
        format!("site:github.com/\"{v}\" OR site:gitlab.com/\"{v}\""),
        format!("site:github.com \"{v}\" password OR secret OR api_key"),
        // Paste sites
        format!("\"{v}\" site:pastebin.com credentials OR email OR password"),
        // Credentials in code
        format!("site:github.com \"{v}\" inurl:.env OR inurl:config.json"),
        // Exposed personal tokens
        format!("site:github.com \"{v}\" \"ghp_\" OR \"github_pat_\" OR \"token\""),
    ]
}

fn org_exposure(v: &str) -> Vec<String> {
    vec![
        // Code repo leaks
        format!("site:github.com \"{v}\" inurl:.env OR inurl:credentials"),
        format!("site:github.com \"{v}\" \"aws_access_key\" OR \"PRIVATE_KEY\""),
        // Cloud storage
        format!("site:s3.amazonaws.com \"{v}\""),
        format!("site:blob.core.windows.net \"{v}\""),
        // Regulatory/compliance exposure
        format!("\"{v}\" filetype:pdf confidential OR internal OR proprietary"),
        // Employee data
        format!("\"{v}\" site:pastebin.com email OR employee OR password"),
    ]
}

fn phone_exposure(v: &str) -> Vec<String> {
    vec![
        // Credential/breach dumps naming this number
        format!("\"{v}\" site:pastebin.com password OR leaked OR breach"),
        format!("\"{v}\" site:dehashed.com OR site:leakcheck.io OR site:snusbase.com"),
        // Code repos accidentally committing an SMS/2FA config with the number
        format!("site:github.com \"{v}\" inurl:.env OR inurl:config.json"),
        // Cloud storage exposure
        format!("site:s3.amazonaws.com \"{v}\""),
        // People-search aggregators
        format!("\"{v}\" site:truepeoplesearch.com OR site:fastpeoplesearch.com"),
    ]
}

fn fullname_exposure(v: &str) -> Vec<String> {
    vec![
        // Credential/breach dumps naming the subject
        format!("\"{v}\" site:pastebin.com password OR email OR leaked"),
        format!("\"{v}\" site:dehashed.com OR site:leakcheck.io OR site:snusbase.com"),
        // Code repos exposing personal documents (resumes, internal docs)
        format!("site:github.com \"{v}\" resume OR cv OR inurl:.env"),
        // Leaked/confidential documents naming the subject
        format!("\"{v}\" filetype:pdf confidential OR internal OR resume"),
        // People-search aggregators
        format!("\"{v}\" site:truepeoplesearch.com OR site:fastpeoplesearch.com"),
    ]
}

fn address_exposure(v: &str) -> Vec<String> {
    vec![
        // Credential/breach dumps naming the address (a common secondary
        // identity field in breach records alongside email/phone).
        format!("\"{v}\" site:pastebin.com password OR leaked OR breach"),
        format!("\"{v}\" site:dehashed.com OR site:leakcheck.io OR site:snusbase.com"),
        // Code repos/configs accidentally committing the address (shipping
        // labels, customer records, KYC data).
        format!("site:github.com \"{v}\" inurl:.env OR inurl:config.json"),
        // Cloud storage exposure
        format!("site:s3.amazonaws.com \"{v}\""),
        // People-search aggregators
        format!("\"{v}\" site:truepeoplesearch.com OR site:fastpeoplesearch.com"),
    ]
}

fn ip_exposure(v: &str) -> Vec<String> {
    vec![
        // Shodan/Censys data (search their public interfaces)
        format!("\"{v}\" site:shodan.io"),
        format!("\"{v}\" site:censys.io"),
        format!("\"{v}\" site:fofa.info OR site:zoomeye.org"),
        // Exposed services
        format!("\"{v}\" inurl:\"8080\" OR inurl:\"8443\" OR inurl:\"9090\""),
        format!("\"{v}\" intext:\"powered by\" OR intext:\"Apache\" OR intext:\"nginx\""),
        // CVE/vuln reports
        format!("\"{v}\" CVE OR vulnerability site:vulners.com OR site:exploit-db.com"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::{Target, TargetKind};

    // ── build_queries_exposure dispatcher ────────────────────────────────────

    #[test]
    fn build_queries_exposure_domain_targets_env_files() {
        let q = build_queries_exposure(&Target::new(TargetKind::Domain, "example.com"));
        assert!(!q.is_empty());
        assert!(q.iter().any(|s| s.contains("inurl:.env")));
    }

    #[test]
    fn build_queries_exposure_email_targets_repos() {
        let q = build_queries_exposure(&Target::new(TargetKind::Email, "alice@acme.com"));
        assert!(!q.is_empty());
        assert!(q.iter().any(|s| s == "site:github.com \"alice@acme.com\""));
    }

    #[test]
    fn build_queries_exposure_username_targets_personal_tokens() {
        let q = build_queries_exposure(&Target::new(TargetKind::Username, "jdoe"));
        assert!(!q.is_empty());
        assert!(q.iter().any(|s| s.contains("\"ghp_\" OR \"github_pat_\"")));
    }

    #[test]
    fn build_queries_exposure_org_targets_cloud_storage() {
        let q = build_queries_exposure(&Target::new(TargetKind::Organisation, "Acme Corp"));
        assert!(!q.is_empty());
        assert!(
            q.iter()
                .any(|s| s == "site:blob.core.windows.net \"Acme Corp\"")
        );
    }

    #[test]
    fn build_queries_exposure_ip_targets_recon_engines() {
        let q = build_queries_exposure(&Target::new(TargetKind::IpAddress, "8.8.8.8"));
        assert!(!q.is_empty());
        assert!(q.iter().any(|s| s == "\"8.8.8.8\" site:shodan.io"));
    }

    #[test]
    fn build_queries_exposure_phone_targets_breach_dumps() {
        let q = build_queries_exposure(&Target::new(TargetKind::Phone, "+61412345678"));
        assert!(!q.is_empty());
        assert!(
            q.iter()
                .any(|s| s.contains("site:dehashed.com") && s.contains("+61412345678"))
        );
    }

    #[test]
    fn build_queries_exposure_fullname_targets_breach_dumps() {
        let q = build_queries_exposure(&Target::new(TargetKind::FullName, "Jordan Avery"));
        assert!(!q.is_empty());
        assert!(
            q.iter()
                .any(|s| s.contains("site:dehashed.com") && s.contains("Jordan Avery"))
        );
    }

    #[test]
    fn build_queries_exposure_address_targets_breach_dumps() {
        let q = build_queries_exposure(&Target::new(
            TargetKind::Address,
            "123 Main St, Springfield",
        ));
        assert!(!q.is_empty());
        assert!(
            q.iter()
                .any(|s| s.contains("site:dehashed.com") && s.contains("123 Main St, Springfield"))
        );
    }

    #[test]
    fn build_queries_exposure_unhandled_kind_is_empty() {
        // Coordinates is one of the explicitly-unsupported kinds (per the doc
        // comment) and hits the `_ => Vec::new()` arm.
        assert!(
            build_queries_exposure(&Target::new(TargetKind::Coordinates, "1.0,2.0")).is_empty()
        );
    }

    // ── per-kind helpers (deterministic dork shapes) ─────────────────────────

    #[test]
    fn domain_exposure_shape() {
        let q = domain_exposure("example.com");
        assert!(
            q.iter()
                .any(|s| s == "site:s3.amazonaws.com \"example.com\"")
        );
        assert!(
            q.iter()
                .any(|s| s == "inurl:\"/.git/config\" site:example.com")
        );
        assert!(q.iter().any(|s| s.contains("inurl:docker-compose.yml")));
    }

    #[test]
    fn username_exposure_shape() {
        let q = username_exposure("jdoe");
        assert_eq!(q.len(), 5);
        assert!(
            q.iter()
                .any(|s| s == "site:github.com/\"jdoe\" OR site:gitlab.com/\"jdoe\"")
        );
        assert!(
            q.iter()
                .any(|s| s == "\"jdoe\" site:pastebin.com credentials OR email OR password")
        );
    }

    #[test]
    fn org_exposure_shape() {
        let q = org_exposure("Acme Corp");
        assert_eq!(q.len(), 6);
        assert!(
            q.iter()
                .any(|s| s == "site:blob.core.windows.net \"Acme Corp\"")
        );
        assert!(
            q.iter()
                .any(|s| s == "\"Acme Corp\" filetype:pdf confidential OR internal OR proprietary")
        );
    }

    #[test]
    fn ip_exposure_shape() {
        let q = ip_exposure("8.8.8.8");
        assert_eq!(q.len(), 6);
        assert!(q.iter().any(|s| s == "\"8.8.8.8\" site:shodan.io"));
        assert!(q.iter().any(|s| s == "\"8.8.8.8\" site:censys.io"));
    }

    #[test]
    fn phone_exposure_shape() {
        let q = phone_exposure("+61412345678");
        assert_eq!(q.len(), 5);
        assert!(q.iter().any(
            |s| s == "\"+61412345678\" site:truepeoplesearch.com OR site:fastpeoplesearch.com"
        ));
        assert!(
            q.iter()
                .any(|s| s.contains("site:s3.amazonaws.com") && s.contains("+61412345678"))
        );
    }

    #[test]
    fn fullname_exposure_shape() {
        let q = fullname_exposure("Jordan Avery");
        assert_eq!(q.len(), 5);
        assert!(q.iter().any(
            |s| s == "\"Jordan Avery\" site:truepeoplesearch.com OR site:fastpeoplesearch.com"
        ));
        assert!(
            q.iter()
                .any(|s| s == "\"Jordan Avery\" filetype:pdf confidential OR internal OR resume")
        );
    }

    #[test]
    fn address_exposure_shape() {
        let q = address_exposure("123 Main St, Springfield");
        assert_eq!(q.len(), 5);
        assert!(q.iter().any(|s| s
            == "\"123 Main St, Springfield\" site:truepeoplesearch.com OR site:fastpeoplesearch.com"));
        assert!(
            q.iter()
                .any(|s| s.contains("site:s3.amazonaws.com") && s.contains("123 Main St"))
        );
    }

    // ── email_exposure: local.len() >= 3 branch ──────────────────────────────

    #[test]
    fn email_exposure_long_local_adds_extra_dorks() {
        // local = "john" (len 4 ≥ 3) → the two extra local-part dorks appear.
        let q = email_exposure("john@x.com");
        assert!(
            q.iter()
                .any(|s| s == "site:github.com \"john\" email OR contact")
        );
        assert!(
            q.iter()
                .any(|s| s == "\"john\" site:gist.github.com password OR key")
        );
    }

    #[test]
    fn email_exposure_short_local_omits_extra_dorks() {
        // local = "ab" (len 2 < 3) → the local-part dorks are NOT added.
        let q = email_exposure("ab@x.com");
        assert!(
            !q.iter()
                .any(|s| s.contains("site:gist.github.com password OR key"))
        );
        assert!(!q.iter().any(|s| s.contains("\"ab\" email OR contact")));
        // The base 6 dorks (independent of local length) are still present.
        assert_eq!(q.len(), 6);
    }
}
