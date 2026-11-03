//! Canonical inventory for the nine security-tool compatibility families.
//! This is a capability registry, not a claim of feature-equivalent ports.
//! No subprocesses, root privileges, or network operations are performed here.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    ExistingRustCapability,
    Planned,
    RequiresPrivilegedHardware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolFamily {
    pub name: &'static str,
    pub capability: &'static str,
    pub availability: Availability,
    pub android_note: &'static str,
}

pub const TOOL_FAMILIES: [ToolFamily; 9] = [
    ToolFamily { name: "john", capability: "Offline password hash audit", availability: Availability::Planned, android_note: "CPU-only; authorization and bounded workloads required" },
    ToolFamily { name: "burp", capability: "HTTP request inspection and passive analysis", availability: Availability::Planned, android_note: "Loopback proxy possible; system-wide TLS interception needs explicit trust configuration" },
    ToolFamily { name: "sqlmap", capability: "SQL injection detection for owned test applications", availability: Availability::Planned, android_note: "Constrain requests to explicitly approved targets" },
    ToolFamily { name: "dirb", capability: "HTTP content discovery", availability: Availability::Planned, android_note: "Bounded concurrency and request budgets" },
    ToolFamily { name: "hashcat", capability: "Password hash auditing", availability: Availability::Planned, android_note: "GPU parity unavailable in ordinary rootless Termux; CPU-only fallback" },
    ToolFamily { name: "aircrack-ng", capability: "Wireless capture and protocol analysis", availability: Availability::RequiresPrivilegedHardware, android_note: "Monitor mode and injection generally unavailable in rootless Android; analyze imported captures" },
    ToolFamily { name: "subfinder", capability: "Passive subdomain enumeration", availability: Availability::Planned, android_note: "Public-source API adapters and rate limits" },
    ToolFamily { name: "exiftool", capability: "Local file metadata extraction", availability: Availability::ExistingRustCapability, android_note: "Existing HSE EXIF module; feature parity not established" },
    ToolFamily { name: "theharvester", capability: "Public-source domain and infrastructure OSINT", availability: Availability::ExistingRustCapability, android_note: "Existing HSE OSINT adapters; feature parity not established" },
];

pub fn find(name: &str) -> Option<&'static ToolFamily> {
    TOOL_FAMILIES.iter().find(|tool| tool.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_nine_families_have_unique_names() {
        assert_eq!(TOOL_FAMILIES.len(), 9);
        for (i, family) in TOOL_FAMILIES.iter().enumerate() {
            assert!(!family.capability.is_empty());
            assert!(!family.android_note.is_empty());
            assert!(TOOL_FAMILIES[..i].iter().all(|other| other.name != family.name));
            assert_eq!(find(family.name), Some(family));
        }
    }

    #[test]
    fn case_insensitive_lookup_and_unknown_tool() {
        assert_eq!(find("EXIFTOOL").map(|t| t.name), Some("exiftool"));
        assert!(find("not-a-tool").is_none());
    }
}
