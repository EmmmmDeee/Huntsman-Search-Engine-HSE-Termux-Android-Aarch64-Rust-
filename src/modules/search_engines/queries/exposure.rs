//! Exposure-focused dork queries — API keys, credentials, cloud storage,
//! code repository leaks. These supplement `build_queries_base` with a
//! separate pass targeting unintentional data exposure rather than identity
//! discovery.

use crate::core::scan::{Target, TargetKind};

/// Build exposure-focused supplementary dork queries for a target.
///
/// These target secrets leaking via code repos, cloud storage, paste sites,
/// and misconfigured servers. Returns an empty Vec for target kinds where
/// exposure dorking is not applicable (Coordinates, ASN, ABN/ACN).
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
        _ => Vec::new(),
    }
}

fn domain_exposure(v: &str) -> Vec<String> {
    vec![
        // Exposed environment files
        format!(
            "site:github.com \"{v}\" filename:.env OR filename:.env.production OR filename:.env.local"
        ),
        format!(
            "site:github.com \"{v}\" filename:wp-config.php OR filename:config.php OR filename:settings.py"
        ),
        // AWS/cloud credentials
        format!("site:github.com \"{v}\" filename:credentials OR filename:aws.config"),
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
        format!("site:github.com \"{v}\" filename:docker-compose.yml OR filename:Dockerfile"),
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
        format!("site:github.com \"{v}\" filename:.env OR filename:config.json"),
        // Exposed personal tokens
        format!("site:github.com \"{v}\" \"ghp_\" OR \"github_pat_\" OR \"token\""),
    ]
}

fn org_exposure(v: &str) -> Vec<String> {
    vec![
        // Code repo leaks
        format!("site:github.com \"{v}\" filename:.env OR filename:credentials"),
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
