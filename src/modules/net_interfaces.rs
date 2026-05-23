//! Local network interface enumerator — reads `/sys/class/net/*/address`
//! (MAC) and `/sys/class/net/*/operstate`. Pure file I/O, no termux-api,
//! no network traffic — passive sensor.
//!
//! Off-Linux hosts (macOS, Windows) lack `/sys/class/net` and no-op cleanly.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::Target,
};

pub struct NetInterfaces;

#[async_trait]
impl Module for NetInterfaces {
    fn name(&self) -> &'static str {
        "net_interfaces"
    }
    fn priority(&self) -> u8 {
        55
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        // not Linux — no-op
        let Ok(mut entries) = tokio::fs::read_dir("/sys/class/net").await else {
            return Ok(result);
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let iface = entry.file_name().to_string_lossy().to_string();
            // Skip loopback by name — its MAC is always all-zero, also skipped
            // by the placeholder check below, but this saves a file read.
            if iface == "lo" {
                continue;
            }

            let mac_path = entry.path().join("address");
            let mac = match tokio::fs::read_to_string(&mac_path).await {
                Ok(s) => s.trim().to_lowercase(),
                Err(_) => continue,
            };
            if mac.is_empty() || mac == "00:00:00:00:00:00" {
                continue;
            }

            let state_path = entry.path().join("operstate");
            let state = tokio::fs::read_to_string(&state_path)
                .await
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".into());

            let mut e = Entity::new(EntityKind::MacAddress, &mac, 0.95, &ctx.scan_id);
            e.tag("local-interface");
            e.add_evidence(
                Evidence::new(
                    "net_interfaces",
                    format!("Local interface {iface} ({state})"),
                )
                .with_attr("interface", &iface)
                .with_attr("operstate", &state),
            );
            result.push(e);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn is_passive() {
        assert!(NetInterfaces.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(NetInterfaces.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }
}
