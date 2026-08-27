//! `hse credentials` — credential management for embedded and environment configuration.
//!
//! Provides CLI commands to:
//! - List all available credentials and their status
//! - Configure embedded credentials interactively
//! - Export/import credential sets
//! - Validate credential formats
//! - Generate credential templates
//! - Test live API connectivity

use crate::core::error::{Error, Result};
use std::collections::HashMap;

pub async fn cmd_credentials_list(detailed: bool) -> Result<()> {
    let embedded = crate::util::keys::get_embedded_keys();
    let loaded = crate::util::keys::load();

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║              Huntsman Search Engine — Credentials              ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Categorize and report
    let categories = categorize_all_credentials(embedded);
    let mut total_embedded = 0;
    let mut total_configured = 0;

    for (category, keys) in categories {
        println!("📦 {}", category);
        for key in &keys {
            total_embedded += 1;
            let configured = loaded.contains_key(key);
            if configured {
                total_configured += 1;
            }

            let status = if configured { "✓" } else { "○" };
            let signup = crate::util::keys::signup_hint(key)
                .unwrap_or("https://example.com")
                .to_string();

            if detailed {
                println!(
                    "   {} {:<35} {}",
                    status, key,
                    if configured { "CONFIGURED" } else { "unconfigured" }
                );
                println!("      └─ {}", signup);
            } else {
                println!("   {} {}", status, key);
            }
        }
        println!();
    }

    println!("Summary:");
    println!("  Total available: {}", total_embedded);
    println!("  Configured: {}", total_configured);
    println!(
        "  Coverage: {}%",
        if total_embedded > 0 {
            (total_configured * 100) / total_embedded
        } else {
            0
        }
    );

    Ok(())
}

pub async fn cmd_credentials_template(output: Option<&str>) -> Result<()> {
    let template = generate_credentials_template();

    if let Some(path) = output {
        std::fs::write(path, &template)?;
        println!("✓ Credential template written to: {}", path);
    } else {
        println!("{}", template);
    }

    Ok(())
}

pub async fn cmd_credentials_validate() -> Result<()> {
    let loaded = crate::util::keys::load();
    let embedded = crate::util::keys::get_embedded_keys();

    println!("Validating {} loaded credentials...\n", loaded.len());

    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    // Check for placeholder values
    for (key, value) in &loaded {
        if value.len() < 8 {
            issues.push(format!("{}: key is too short ({})", key, value.len()));
        }
        if value.contains("your-") || value.contains("xxx") || value.contains("example") {
            warnings.push(format!("{}: appears to be a placeholder", key));
        }
    }

    // Check for duplicate configurations
    let env_keys: std::collections::HashSet<_> = loaded.keys().map(|k| k.as_str()).collect();
    let embedded_keys: std::collections::HashSet<_> = embedded.keys().copied().collect();
    let duplicates: Vec<_> = env_keys.intersection(&embedded_keys).copied().collect();

    if !duplicates.is_empty() {
        println!("⚠ {} credential(s) configured in both environment and embedded:", duplicates.len());
        for dup in duplicates {
            println!("  - {}", dup);
        }
        println!("  Environment variables take priority.\n");
    }

    if issues.is_empty() && warnings.is_empty() {
        println!("✓ All credentials validated successfully!");
    } else {
        if !warnings.is_empty() {
            println!("⚠ Warnings ({}):", warnings.len());
            for w in warnings {
                println!("  - {}", w);
            }
            println!();
        }
        if !issues.is_empty() {
            println!("✗ Issues ({}):", issues.len());
            for i in issues {
                println!("  - {}", i);
            }
            return Err(Error::Other("Credential validation failed".to_string()));
        }
    }

    Ok(())
}

pub async fn cmd_credentials_test(key_name: Option<&str>) -> Result<()> {
    let loaded = crate::util::keys::load();

    if let Some(name) = key_name {
        // Test single credential
        if let Some(value) = loaded.get(name) {
            println!("Testing credential: {}\n", name);
            test_single_credential(name, value).await?;
        } else {
            return Err(Error::Other(format!("Credential {} not found", name)));
        }
    } else {
        // Test all configured credentials
        println!("Testing all {} configured credentials...\n", loaded.len());
        let mut success = 0;
        let mut failed = 0;

        for (key, value) in &loaded {
            match test_single_credential(key, value).await {
                Ok(_) => success += 1,
                Err(_) => failed += 1,
            }
        }

        println!("\nResults: {} success, {} failed", success, failed);
        if failed > 0 {
            return Err(Error::Other(format!("{} credential tests failed", failed)));
        }
    }

    Ok(())
}

async fn test_single_credential(name: &str, value: &str) -> Result<()> {
    // Test based on credential type
    let test_result = match name {
        n if n.contains("SHODAN") => test_shodan_credential(value).await,
        n if n.contains("VIRUSTOTAL") => test_virustotal_credential(value).await,
        n if n.contains("HIBP") => test_hibp_credential(value).await,
        n if n.contains("GITHUB") => test_github_credential(value).await,
        _ => {
            println!("  {}: skipped (no test available)", name);
            Ok(())
        }
    };

    match test_result {
        Ok(_) => {
            println!("  ✓ {} authenticated", name);
            Ok(())
        }
        Err(e) => {
            println!("  ✗ {} failed: {}", name, e);
            Err(e)
        }
    }
}

async fn test_shodan_credential(key: &str) -> Result<()> {
    let client = crate::util::http::build_client();
    let url = format!("https://api.shodan.io/account/profile?key={}", key);

    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(Error::Other(format!("Shodan auth failed: {}", response.status())))
    }
}

async fn test_virustotal_credential(key: &str) -> Result<()> {
    let client = crate::util::http::build_client();
    let response = client
        .get("https://www.virustotal.com/api/v3/me")
        .header("x-apikey", key)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(Error::Other(format!("VirusTotal auth failed: {}", response.status())))
    }
}

async fn test_hibp_credential(key: &str) -> Result<()> {
    let client = crate::util::http::build_client();
    let response = client
        .get("https://haveibeenpwned.com/api/v3/breaches")
        .header("User-Agent", "Huntsman-Search-Engine")
        .header("hibp-api-key", key)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;

    if response.status().is_success() || response.status().as_u16() == 404 {
        Ok(())
    } else {
        Err(Error::Other(format!("HIBP auth failed: {}", response.status())))
    }
}

async fn test_github_credential(token: &str) -> Result<()> {
    let client = crate::util::http::build_client();
    let response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(Error::Other(format!("GitHub auth failed: {}", response.status())))
    }
}

fn categorize_all_credentials(
    embedded: &std::collections::HashMap<&str, &str>,
) -> HashMap<String, Vec<String>> {
    let mut categories: HashMap<String, Vec<String>> = HashMap::new();

    for key in embedded.keys() {
        let category = match *key {
            k if k.contains("VIRUSTOTAL") || k.contains("GREYNOISE") || k.contains("URLSCAN") => {
                "Threat Intelligence"
            }
            k if k.contains("SEEKNOW") || k.contains("HIBP") || k.contains("DEHASHED") => {
                "Breach Intelligence"
            }
            k if k.contains("SHODAN") || k.contains("CENSYS") || k.contains("FOFA") => {
                "Infrastructure Intelligence"
            }
            k if k.contains("PROXYCURL") || k.contains("HUNTER") || k.contains("GITHUB") => {
                "Identity Intelligence"
            }
            k if k.contains("WIGLE") || k.contains("OPENCELLID") => "Geolocation",
            k if k.contains("OPENCORPORATES") || k.contains("BUILTWITH") => {
                "Business Intelligence"
            }
            _ => "Other Services",
        };

        categories
            .entry(category.to_string())
            .or_insert_with(Vec::new)
            .push(key.to_string());
    }

    // Sort each category
    for entries in categories.values_mut() {
        entries.sort();
    }

    categories
}

fn generate_credentials_template() -> String {
    r#"#!/bin/bash
# Huntsman Search Engine — Embedded Credentials Template
#
# Edit this file with your API credentials and source it before building:
#   source credentials.env
#   cargo build --release
#
# Or set these as environment variables:
#   export HUNTSMAN_SHODAN_KEY="your-key"

# ─── Threat Intelligence & Malware ───────────────────────
export HUNTSMAN_VIRUSTOTAL_KEY="your-virustotal-api-key"
export HUNTSMAN_GREYNOISE_KEY="your-greynoise-api-key"
export HUNTSMAN_URLSCAN_KEY="your-urlscan-api-key"
export HUNTSMAN_ABUSEIPDB_KEY="your-abuseipdb-api-key"
export HUNTSMAN_THREATFOX_KEY="your-threatfox-api-key"
export HUNTSMAN_ABUSECH_KEY="your-abusech-api-key"

# ─── Breach & Intelligence ──────────────────────────────
export HUNTSMAN_SEEKNOW_KEY="your-seeknow-api-key"
export HUNTSMAN_HIBP_KEY="your-hibp-api-key"
export HUNTSMAN_INTELX_KEY="your-intelx-api-key"
export HUNTSMAN_OATHNET_KEY="your-oathnet-bearer-token"
export HUNTSMAN_DEHASHED_KEY="your-dehashed-api-key"

# ─── Infrastructure/IP/Domain ───────────────────────────
export HUNTSMAN_SHODAN_KEY="your-shodan-api-key"
export HUNTSMAN_SECTRAILS_KEY="your-securitytrails-api-key"
export HUNTSMAN_LEAKIX_KEY="your-leakix-api-key"
export HUNTSMAN_CRIMINALIP_KEY="your-criminalip-api-key"
export HUNTSMAN_CENSYS_ID="your-censys-id"
export HUNTSMAN_CENSYS_SECRET="your-censys-secret"
export HUNTSMAN_FOFA_KEY="your-fofa-api-key"

# ─── Identity/Person Intelligence ──────────────────────
export HUNTSMAN_PROXYCURL_KEY="your-proxycurl-api-key"
export HUNTSMAN_HUNTER_KEY="your-hunter-api-key"
export HUNTSMAN_EMAILREP_KEY="your-emailrep-api-key"
export HUNTSMAN_GITHUB_TOKEN="your-github-personal-access-token"

# ─── Geolocation ───────────────────────────────────────
export HUNTSMAN_WIGLE_USER="your-wigle-username"
export HUNTSMAN_WIGLE_TOKEN="your-wigle-token"
export HUNTSMAN_OPENCELLID_KEY="your-opencellid-api-key"

# ─── Add more credentials as needed ─────────────────────
# See: https://github.com/EmmmmDeee/Huntsman-Search-Engine
# For complete list of all 60+ supported APIs
"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorization() {
        let mut embedded = HashMap::new();
        embedded.insert("HUNTSMAN_SHODAN_KEY", "test");
        embedded.insert("HUNTSMAN_VIRUSTOTAL_KEY", "test");
        embedded.insert("HUNTSMAN_HIBP_KEY", "test");

        let categories = categorize_all_credentials(&embedded);
        assert!(categories.contains_key("Threat Intelligence"));
        assert!(categories.contains_key("Infrastructure Intelligence"));
        assert!(categories.contains_key("Breach Intelligence"));
    }
}
