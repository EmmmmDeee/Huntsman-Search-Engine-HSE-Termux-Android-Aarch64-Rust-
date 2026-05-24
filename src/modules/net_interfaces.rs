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
    fn description(&self) -> &'static str {
        "Local network interface enumeration"
    }
    fn priority(&self) -> u8 {
        55
    }

    fn description(&self) -> &'static str {
        "Termux network interface enumeration — IPv4/IPv6 addresses per interface (eth0, wlan0, …). Passive."
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
            let iface_os = entry.file_name();
            // Skip loopback by name — its MAC is always all-zero, also skipped
            // by the placeholder check below, but this saves a file read.
            if iface_os == "lo" {
                continue;
            }

            let dir = entry.path();
            let mac = match tokio::fs::read_to_string(dir.join("address")).await {
                Ok(s) => s.trim().to_lowercase(),
                Err(_) => continue,
            };
            if mac.is_empty() || mac == "00:00:00:00:00:00" {
                continue;
            }

            let state = tokio::fs::read_to_string(dir.join("operstate"))
                .await
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".into());

            let iface = iface_os.to_string_lossy();
            let mut e = Entity::new(EntityKind::MacAddress, &mac, 0.95, &ctx.scan_id);
            e.tag("local-interface");
            e.add_evidence(
                Evidence::new(
                    "net_interfaces",
                    format!("Local interface {iface} ({state})"),
                )
                .with_attr("interface", iface.as_ref())
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

    #[test]
    fn module_name() {
        assert_eq!(NetInterfaces.name(), "net_interfaces");
    }

    #[test]
    fn module_priority() {
        assert_eq!(NetInterfaces.priority(), 55);
    }

    #[test]
    fn accepts_all_target_kinds() {
        assert!(NetInterfaces.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(NetInterfaces.accepts(&Target::new(TargetKind::IpAddress, "10.0.0.1")));
        assert!(NetInterfaces.accepts(&Target::new(TargetKind::Username, "user1")));
    }

    #[test]
    fn cost_is_free() {
        use crate::core::module::ModuleCost;
        assert_eq!(NetInterfaces.cost(), ModuleCost::Free);
    }

    #[test]
    fn info_aggregates_metadata() {
        let info = NetInterfaces.info();
        assert_eq!(info.name, "net_interfaces");
        assert_eq!(info.priority, 55);
        assert!(info.passive);
    }
}
