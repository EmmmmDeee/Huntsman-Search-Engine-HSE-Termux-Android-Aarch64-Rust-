//! MITRE ATT&CK® catalogue — the **complete Enterprise matrix** as reference
//! vocabulary, plus HSE's honest **Reconnaissance** coverage.
//!
//! Two distinct things live here, and keeping them distinct is the whole point:
//!
//! 1. **The framework** ([`TACTICS`] + [`ENTERPRISE`]): the entire MITRE ATT&CK
//!    Enterprise matrix — all 14 tactics and every current technique /
//!    sub-technique ([`ATTACK_VERSION`]) — as pure static data. This lets a finding, an
//!    evidence trail, or a correlation edge be labelled with *any* ATT&CK
//!    technique in the standard vocabulary, and lets an operator resolve any
//!    `Tnnnn[.nnn]` id the tool emits to its canonical name and owning tactic(s).
//!
//! 2. **HSE's coverage** ([`reconnaissance`] / [`uncovered`] /
//!    [`techniques_for_category`]): the slice HSE actually *performs* — the
//!    Reconnaissance tactic (TA0043). HSE is a passive-and-authorised OSINT
//!    *collector*; it gathers victim identity / network / org / host information
//!    and searches open sites and technical databases. Those are Reconnaissance
//!    techniques, so that is the only tactic HSE claims coverage of.
//!
//! Holding the *whole* framework while claiming coverage of *one* tactic is not a
//! contradiction — it is the invariant. Reference vocabulary is not a coverage
//! assertion: a module may tag a finding with a Collection or Resource-Development
//! technique when that is literally what the datum is, without HSE pretending to
//! perform those tactics end-to-end. The one thing this evidentiary tool must
//! never do is claim *coverage* it does not have, so [`uncovered`] and the
//! per-scan coverage report are computed against the Reconnaissance tactic alone —
//! a technique HSE performs no collection for (e.g. `T1598` Phishing for
//! Information) surfaces as a real, named gap rather than being silently absent.
//!
//! Pure data + lookups; no runtime I/O (the multi-MB STIX bundle is NOT vendored —
//! only the id/name/tactic triples are, regenerated from the pinned release).
//! Drift-guard tests pin that the Reconnaissance slice is exactly the full TA0043
//! tactic, that every id the module map references exists in the catalogue, and
//! that the catalogue stays sorted and duplicate-free.

use crate::core::module::ModuleCategory;
use serde::Serialize;

/// The ATT&CK release these triples were generated from. Bump alongside a
/// regeneration of [`TACTICS`] / [`ENTERPRISE`] from the pinned STIX bundle.
pub const ATTACK_VERSION: &str = "17.1";

/// The MITRE ATT&CK tactic HSE performs collection for — the one tactic whose
/// *coverage* the tool honestly claims. Retained as the canonical pair the
/// coverage report and dossier key on.
pub const TACTIC_ID: &str = "TA0043";
/// Human-readable name of [`TACTIC_ID`].
pub const TACTIC_NAME: &str = "Reconnaissance";

/// One MITRE ATT&CK Enterprise tactic (a column of the matrix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Tactic {
    /// Canonical ATT&CK tactic ID, e.g. `TA0043`.
    pub id: &'static str,
    /// STIX `x_mitre_shortname`, e.g. `reconnaissance` — the key a technique's
    /// [`Technique::tactics`] membership uses.
    pub shortname: &'static str,
    /// Tactic name, e.g. "Reconnaissance".
    pub name: &'static str,
}

/// One ATT&CK technique or sub-technique. `id` is the canonical ATT&CK
/// identifier; sub-techniques use the dotted form (`T1596.002`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Technique {
    /// Canonical ATT&CK ID, e.g. `T1589.002`.
    pub id: &'static str,
    /// ATT&CK technique name, e.g. "Email Addresses".
    pub name: &'static str,
    /// True for a sub-technique (dotted id) — a leaf under a parent technique.
    pub is_subtechnique: bool,
    /// The `shortname`s of every tactic this technique belongs to (a technique
    /// can sit in several matrix columns), sorted for stable output.
    pub tactics: &'static [&'static str],
}

/// The complete MITRE ATT&CK Enterprise tactic list (all 14), sorted by `id`.
pub const TACTICS: &[Tactic] = &[
    Tactic {
        id: "TA0001",
        shortname: "initial-access",
        name: "Initial Access",
    },
    Tactic {
        id: "TA0002",
        shortname: "execution",
        name: "Execution",
    },
    Tactic {
        id: "TA0003",
        shortname: "persistence",
        name: "Persistence",
    },
    Tactic {
        id: "TA0004",
        shortname: "privilege-escalation",
        name: "Privilege Escalation",
    },
    Tactic {
        id: "TA0005",
        shortname: "defense-evasion",
        name: "Defense Evasion",
    },
    Tactic {
        id: "TA0006",
        shortname: "credential-access",
        name: "Credential Access",
    },
    Tactic {
        id: "TA0007",
        shortname: "discovery",
        name: "Discovery",
    },
    Tactic {
        id: "TA0008",
        shortname: "lateral-movement",
        name: "Lateral Movement",
    },
    Tactic {
        id: "TA0009",
        shortname: "collection",
        name: "Collection",
    },
    Tactic {
        id: "TA0010",
        shortname: "exfiltration",
        name: "Exfiltration",
    },
    Tactic {
        id: "TA0011",
        shortname: "command-and-control",
        name: "Command and Control",
    },
    Tactic {
        id: "TA0040",
        shortname: "impact",
        name: "Impact",
    },
    Tactic {
        id: "TA0042",
        shortname: "resource-development",
        name: "Resource Development",
    },
    Tactic {
        id: "TA0043",
        shortname: "reconnaissance",
        name: "Reconnaissance",
    },
];

/// The complete MITRE ATT&CK Enterprise technique catalogue ([`ATTACK_VERSION`])
/// — every current technique and sub-technique, sorted by `id` for stable output
/// and easy review. This is reference vocabulary for the WHOLE framework; HSE's
/// claimed *coverage* is a strict subset ([`reconnaissance`]).
pub const ENTERPRISE: &[Technique] = &[
    Technique {
        id: "T1001",
        name: "Data Obfuscation",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1001.001",
        name: "Junk Data",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1001.002",
        name: "Steganography",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1001.003",
        name: "Protocol or Service Impersonation",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1003",
        name: "OS Credential Dumping",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1003.001",
        name: "LSASS Memory",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1003.002",
        name: "Security Account Manager",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1003.003",
        name: "NTDS",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1003.004",
        name: "LSA Secrets",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1003.005",
        name: "Cached Domain Credentials",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1003.006",
        name: "DCSync",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1003.007",
        name: "Proc Filesystem",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1003.008",
        name: "/etc/passwd and /etc/shadow",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1005",
        name: "Data from Local System",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1006",
        name: "Direct Volume Access",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1007",
        name: "System Service Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1008",
        name: "Fallback Channels",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1010",
        name: "Application Window Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1011",
        name: "Exfiltration Over Other Network Medium",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1011.001",
        name: "Exfiltration Over Bluetooth",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1012",
        name: "Query Registry",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1014",
        name: "Rootkit",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1016",
        name: "System Network Configuration Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1016.001",
        name: "Internet Connection Discovery",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1016.002",
        name: "Wi-Fi Discovery",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1018",
        name: "Remote System Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1020",
        name: "Automated Exfiltration",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1020.001",
        name: "Traffic Duplication",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1021",
        name: "Remote Services",
        is_subtechnique: false,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1021.001",
        name: "Remote Desktop Protocol",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1021.002",
        name: "SMB/Windows Admin Shares",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1021.003",
        name: "Distributed Component Object Model",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1021.004",
        name: "SSH",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1021.005",
        name: "VNC",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1021.006",
        name: "Windows Remote Management",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1021.007",
        name: "Cloud Services",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1021.008",
        name: "Direct Cloud VM Connections",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1025",
        name: "Data from Removable Media",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1027",
        name: "Obfuscated Files or Information",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.001",
        name: "Binary Padding",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.002",
        name: "Software Packing",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.003",
        name: "Steganography",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.004",
        name: "Compile After Delivery",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.005",
        name: "Indicator Removal from Tools",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.006",
        name: "HTML Smuggling",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.007",
        name: "Dynamic API Resolution",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.008",
        name: "Stripped Payloads",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.009",
        name: "Embedded Payloads",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.010",
        name: "Command Obfuscation",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.011",
        name: "Fileless Storage",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.012",
        name: "LNK Icon Smuggling",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.013",
        name: "Encrypted/Encoded File",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.014",
        name: "Polymorphic Code",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.015",
        name: "Compression",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.016",
        name: "Junk Code Insertion",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1027.017",
        name: "SVG Smuggling",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1029",
        name: "Scheduled Transfer",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1030",
        name: "Data Transfer Size Limits",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1033",
        name: "System Owner/User Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1036",
        name: "Masquerading",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.001",
        name: "Invalid Code Signature",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.002",
        name: "Right-to-Left Override",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.003",
        name: "Rename Legitimate Utilities",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.004",
        name: "Masquerade Task or Service",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.005",
        name: "Match Legitimate Resource Name or Location",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.006",
        name: "Space after Filename",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.007",
        name: "Double File Extension",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.008",
        name: "Masquerade File Type",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.009",
        name: "Break Process Trees",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.010",
        name: "Masquerade Account Name",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1036.011",
        name: "Overwrite Process Arguments",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1037",
        name: "Boot or Logon Initialization Scripts",
        is_subtechnique: false,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1037.001",
        name: "Logon Script (Windows)",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1037.002",
        name: "Login Hook",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1037.003",
        name: "Network Logon Script",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1037.004",
        name: "RC Scripts",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1037.005",
        name: "Startup Items",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1039",
        name: "Data from Network Shared Drive",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1040",
        name: "Network Sniffing",
        is_subtechnique: false,
        tactics: &["credential-access", "discovery"],
    },
    Technique {
        id: "T1041",
        name: "Exfiltration Over C2 Channel",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1046",
        name: "Network Service Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1047",
        name: "Windows Management Instrumentation",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1048",
        name: "Exfiltration Over Alternative Protocol",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1048.001",
        name: "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1048.002",
        name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1048.003",
        name: "Exfiltration Over Unencrypted Non-C2 Protocol",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1049",
        name: "System Network Connections Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1052",
        name: "Exfiltration Over Physical Medium",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1052.001",
        name: "Exfiltration over USB",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1053",
        name: "Scheduled Task/Job",
        is_subtechnique: false,
        tactics: &["execution", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1053.002",
        name: "At",
        is_subtechnique: true,
        tactics: &["execution", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1053.003",
        name: "Cron",
        is_subtechnique: true,
        tactics: &["execution", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1053.005",
        name: "Scheduled Task",
        is_subtechnique: true,
        tactics: &["execution", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1053.006",
        name: "Systemd Timers",
        is_subtechnique: true,
        tactics: &["execution", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1053.007",
        name: "Container Orchestration Job",
        is_subtechnique: true,
        tactics: &["execution", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1055",
        name: "Process Injection",
        is_subtechnique: false,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.001",
        name: "Dynamic-link Library Injection",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.002",
        name: "Portable Executable Injection",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.003",
        name: "Thread Execution Hijacking",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.004",
        name: "Asynchronous Procedure Call",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.005",
        name: "Thread Local Storage",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.008",
        name: "Ptrace System Calls",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.009",
        name: "Proc Memory",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.011",
        name: "Extra Window Memory Injection",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.012",
        name: "Process Hollowing",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.013",
        name: "Process Doppelgänging",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.014",
        name: "VDSO Hijacking",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1055.015",
        name: "ListPlanting",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1056",
        name: "Input Capture",
        is_subtechnique: false,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1056.001",
        name: "Keylogging",
        is_subtechnique: true,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1056.002",
        name: "GUI Input Capture",
        is_subtechnique: true,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1056.003",
        name: "Web Portal Capture",
        is_subtechnique: true,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1056.004",
        name: "Credential API Hooking",
        is_subtechnique: true,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1057",
        name: "Process Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.001",
        name: "PowerShell",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.002",
        name: "AppleScript",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.003",
        name: "Windows Command Shell",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.004",
        name: "Unix Shell",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.005",
        name: "Visual Basic",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.006",
        name: "Python",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.007",
        name: "JavaScript",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.008",
        name: "Network Device CLI",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.009",
        name: "Cloud API",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.010",
        name: "AutoHotKey & AutoIT",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.011",
        name: "Lua",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1059.012",
        name: "Hypervisor CLI",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        is_subtechnique: false,
        tactics: &["privilege-escalation"],
    },
    Technique {
        id: "T1069",
        name: "Permission Groups Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1069.001",
        name: "Local Groups",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1069.002",
        name: "Domain Groups",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1069.003",
        name: "Cloud Groups",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1070",
        name: "Indicator Removal",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.001",
        name: "Clear Windows Event Logs",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.002",
        name: "Clear Linux or Mac System Logs",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.003",
        name: "Clear Command History",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.004",
        name: "File Deletion",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.005",
        name: "Network Share Connection Removal",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.006",
        name: "Timestomp",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.007",
        name: "Clear Network Connection History and Configurations",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.008",
        name: "Clear Mailbox Data",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.009",
        name: "Clear Persistence",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1070.010",
        name: "Relocate Malware",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1071",
        name: "Application Layer Protocol",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1071.001",
        name: "Web Protocols",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1071.002",
        name: "File Transfer Protocols",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1071.003",
        name: "Mail Protocols",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1071.004",
        name: "DNS",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1071.005",
        name: "Publish/Subscribe Protocols",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1072",
        name: "Software Deployment Tools",
        is_subtechnique: false,
        tactics: &["execution", "lateral-movement"],
    },
    Technique {
        id: "T1074",
        name: "Data Staged",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1074.001",
        name: "Local Data Staging",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1074.002",
        name: "Remote Data Staging",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1078",
        name: "Valid Accounts",
        is_subtechnique: false,
        tactics: &[
            "defense-evasion",
            "initial-access",
            "persistence",
            "privilege-escalation",
        ],
    },
    Technique {
        id: "T1078.001",
        name: "Default Accounts",
        is_subtechnique: true,
        tactics: &[
            "defense-evasion",
            "initial-access",
            "persistence",
            "privilege-escalation",
        ],
    },
    Technique {
        id: "T1078.002",
        name: "Domain Accounts",
        is_subtechnique: true,
        tactics: &[
            "defense-evasion",
            "initial-access",
            "persistence",
            "privilege-escalation",
        ],
    },
    Technique {
        id: "T1078.003",
        name: "Local Accounts",
        is_subtechnique: true,
        tactics: &[
            "defense-evasion",
            "initial-access",
            "persistence",
            "privilege-escalation",
        ],
    },
    Technique {
        id: "T1078.004",
        name: "Cloud Accounts",
        is_subtechnique: true,
        tactics: &[
            "defense-evasion",
            "initial-access",
            "persistence",
            "privilege-escalation",
        ],
    },
    Technique {
        id: "T1080",
        name: "Taint Shared Content",
        is_subtechnique: false,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1082",
        name: "System Information Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1083",
        name: "File and Directory Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1087",
        name: "Account Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1087.001",
        name: "Local Account",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1087.002",
        name: "Domain Account",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1087.003",
        name: "Email Account",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1087.004",
        name: "Cloud Account",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1090",
        name: "Proxy",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1090.001",
        name: "Internal Proxy",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1090.002",
        name: "External Proxy",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1090.003",
        name: "Multi-hop Proxy",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1090.004",
        name: "Domain Fronting",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1091",
        name: "Replication Through Removable Media",
        is_subtechnique: false,
        tactics: &["initial-access", "lateral-movement"],
    },
    Technique {
        id: "T1092",
        name: "Communication Through Removable Media",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1095",
        name: "Non-Application Layer Protocol",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1098",
        name: "Account Manipulation",
        is_subtechnique: false,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1098.001",
        name: "Additional Cloud Credentials",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1098.002",
        name: "Additional Email Delegate Permissions",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1098.003",
        name: "Additional Cloud Roles",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1098.004",
        name: "SSH Authorized Keys",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1098.005",
        name: "Device Registration",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1098.006",
        name: "Additional Container Cluster Roles",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1098.007",
        name: "Additional Local or Domain Groups",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1102",
        name: "Web Service",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1102.001",
        name: "Dead Drop Resolver",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1102.002",
        name: "Bidirectional Communication",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1102.003",
        name: "One-Way Communication",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1104",
        name: "Multi-Stage Channels",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1105",
        name: "Ingress Tool Transfer",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1106",
        name: "Native API",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1110",
        name: "Brute Force",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1110.001",
        name: "Password Guessing",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1110.002",
        name: "Password Cracking",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1110.003",
        name: "Password Spraying",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1110.004",
        name: "Credential Stuffing",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1111",
        name: "Multi-Factor Authentication Interception",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1112",
        name: "Modify Registry",
        is_subtechnique: false,
        tactics: &["defense-evasion", "persistence"],
    },
    Technique {
        id: "T1113",
        name: "Screen Capture",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1114",
        name: "Email Collection",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1114.001",
        name: "Local Email Collection",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1114.002",
        name: "Remote Email Collection",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1114.003",
        name: "Email Forwarding Rule",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1115",
        name: "Clipboard Data",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1119",
        name: "Automated Collection",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1120",
        name: "Peripheral Device Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1123",
        name: "Audio Capture",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1124",
        name: "System Time Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1125",
        name: "Video Capture",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1127",
        name: "Trusted Developer Utilities Proxy Execution",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1127.001",
        name: "MSBuild",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1127.002",
        name: "ClickOnce",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1127.003",
        name: "JamPlus",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1129",
        name: "Shared Modules",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1132",
        name: "Data Encoding",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1132.001",
        name: "Standard Encoding",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1132.002",
        name: "Non-Standard Encoding",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1133",
        name: "External Remote Services",
        is_subtechnique: false,
        tactics: &["initial-access", "persistence"],
    },
    Technique {
        id: "T1134",
        name: "Access Token Manipulation",
        is_subtechnique: false,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1134.001",
        name: "Token Impersonation/Theft",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1134.002",
        name: "Create Process with Token",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1134.003",
        name: "Make and Impersonate Token",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1134.004",
        name: "Parent PID Spoofing",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1134.005",
        name: "SID-History Injection",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1135",
        name: "Network Share Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1136",
        name: "Create Account",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1136.001",
        name: "Local Account",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1136.002",
        name: "Domain Account",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1136.003",
        name: "Cloud Account",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1137",
        name: "Office Application Startup",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1137.001",
        name: "Office Template Macros",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1137.002",
        name: "Office Test",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1137.003",
        name: "Outlook Forms",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1137.004",
        name: "Outlook Home Page",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1137.005",
        name: "Outlook Rules",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1137.006",
        name: "Add-ins",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1140",
        name: "Deobfuscate/Decode Files or Information",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1176",
        name: "Software Extensions",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1176.001",
        name: "Browser Extensions",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1176.002",
        name: "IDE Extensions",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1185",
        name: "Browser Session Hijacking",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1187",
        name: "Forced Authentication",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1189",
        name: "Drive-by Compromise",
        is_subtechnique: false,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        is_subtechnique: false,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1195",
        name: "Supply Chain Compromise",
        is_subtechnique: false,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1195.001",
        name: "Compromise Software Dependencies and Development Tools",
        is_subtechnique: true,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1195.002",
        name: "Compromise Software Supply Chain",
        is_subtechnique: true,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1195.003",
        name: "Compromise Hardware Supply Chain",
        is_subtechnique: true,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1197",
        name: "BITS Jobs",
        is_subtechnique: false,
        tactics: &["defense-evasion", "persistence"],
    },
    Technique {
        id: "T1199",
        name: "Trusted Relationship",
        is_subtechnique: false,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1200",
        name: "Hardware Additions",
        is_subtechnique: false,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1201",
        name: "Password Policy Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1202",
        name: "Indirect Command Execution",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1203",
        name: "Exploitation for Client Execution",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1204",
        name: "User Execution",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1204.001",
        name: "Malicious Link",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1204.002",
        name: "Malicious File",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1204.003",
        name: "Malicious Image",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1204.004",
        name: "Malicious Copy and Paste",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1205",
        name: "Traffic Signaling",
        is_subtechnique: false,
        tactics: &["command-and-control", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1205.001",
        name: "Port Knocking",
        is_subtechnique: true,
        tactics: &["command-and-control", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1205.002",
        name: "Socket Filters",
        is_subtechnique: true,
        tactics: &["command-and-control", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1207",
        name: "Rogue Domain Controller",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1210",
        name: "Exploitation of Remote Services",
        is_subtechnique: false,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1211",
        name: "Exploitation for Defense Evasion",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1212",
        name: "Exploitation for Credential Access",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1213",
        name: "Data from Information Repositories",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1213.001",
        name: "Confluence",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1213.002",
        name: "Sharepoint",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1213.003",
        name: "Code Repositories",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1213.004",
        name: "Customer Relationship Management Software",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1213.005",
        name: "Messaging Applications",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1216",
        name: "System Script Proxy Execution",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1216.001",
        name: "PubPrn",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1216.002",
        name: "SyncAppvPublishingServer",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1217",
        name: "Browser Information Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1218",
        name: "System Binary Proxy Execution",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.001",
        name: "Compiled HTML File",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.002",
        name: "Control Panel",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.003",
        name: "CMSTP",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.004",
        name: "InstallUtil",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.005",
        name: "Mshta",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.007",
        name: "Msiexec",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.008",
        name: "Odbcconf",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.009",
        name: "Regsvcs/Regasm",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.010",
        name: "Regsvr32",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.011",
        name: "Rundll32",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.012",
        name: "Verclsid",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.013",
        name: "Mavinject",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.014",
        name: "MMC",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1218.015",
        name: "Electron Applications",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1219",
        name: "Remote Access Tools",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1219.001",
        name: "IDE Tunneling",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1219.002",
        name: "Remote Desktop Software",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1219.003",
        name: "Remote Access Hardware",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1220",
        name: "XSL Script Processing",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1221",
        name: "Template Injection",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1222",
        name: "File and Directory Permissions Modification",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1222.001",
        name: "Windows File and Directory Permissions Modification",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1222.002",
        name: "Linux and Mac File and Directory Permissions Modification",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1480",
        name: "Execution Guardrails",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1480.001",
        name: "Environmental Keying",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1480.002",
        name: "Mutual Exclusion",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1482",
        name: "Domain Trust Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1484",
        name: "Domain or Tenant Policy Modification",
        is_subtechnique: false,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1484.001",
        name: "Group Policy Modification",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1484.002",
        name: "Trust Modification",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1485",
        name: "Data Destruction",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1485.001",
        name: "Lifecycle-Triggered Deletion",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1486",
        name: "Data Encrypted for Impact",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1489",
        name: "Service Stop",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1490",
        name: "Inhibit System Recovery",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1491",
        name: "Defacement",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1491.001",
        name: "Internal Defacement",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1491.002",
        name: "External Defacement",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1495",
        name: "Firmware Corruption",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1496",
        name: "Resource Hijacking",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1496.001",
        name: "Compute Hijacking",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1496.002",
        name: "Bandwidth Hijacking",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1496.003",
        name: "SMS Pumping",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1496.004",
        name: "Cloud Service Hijacking",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1497",
        name: "Virtualization/Sandbox Evasion",
        is_subtechnique: false,
        tactics: &["defense-evasion", "discovery"],
    },
    Technique {
        id: "T1497.001",
        name: "System Checks",
        is_subtechnique: true,
        tactics: &["defense-evasion", "discovery"],
    },
    Technique {
        id: "T1497.002",
        name: "User Activity Based Checks",
        is_subtechnique: true,
        tactics: &["defense-evasion", "discovery"],
    },
    Technique {
        id: "T1497.003",
        name: "Time Based Evasion",
        is_subtechnique: true,
        tactics: &["defense-evasion", "discovery"],
    },
    Technique {
        id: "T1498",
        name: "Network Denial of Service",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1498.001",
        name: "Direct Network Flood",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1498.002",
        name: "Reflection Amplification",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1499",
        name: "Endpoint Denial of Service",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1499.001",
        name: "OS Exhaustion Flood",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1499.002",
        name: "Service Exhaustion Flood",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1499.003",
        name: "Application Exhaustion Flood",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1499.004",
        name: "Application or System Exploitation",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1505",
        name: "Server Software Component",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1505.001",
        name: "SQL Stored Procedures",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1505.002",
        name: "Transport Agent",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1505.003",
        name: "Web Shell",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1505.004",
        name: "IIS Components",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1505.005",
        name: "Terminal Services DLL",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1505.006",
        name: "vSphere Installation Bundles",
        is_subtechnique: true,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1518",
        name: "Software Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1518.001",
        name: "Security Software Discovery",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1525",
        name: "Implant Internal Image",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1526",
        name: "Cloud Service Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1528",
        name: "Steal Application Access Token",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1529",
        name: "System Shutdown/Reboot",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1530",
        name: "Data from Cloud Storage",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1531",
        name: "Account Access Removal",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1534",
        name: "Internal Spearphishing",
        is_subtechnique: false,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1535",
        name: "Unused/Unsupported Cloud Regions",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1537",
        name: "Transfer Data to Cloud Account",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1538",
        name: "Cloud Service Dashboard",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1539",
        name: "Steal Web Session Cookie",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1542",
        name: "Pre-OS Boot",
        is_subtechnique: false,
        tactics: &["defense-evasion", "persistence"],
    },
    Technique {
        id: "T1542.001",
        name: "System Firmware",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence"],
    },
    Technique {
        id: "T1542.002",
        name: "Component Firmware",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence"],
    },
    Technique {
        id: "T1542.003",
        name: "Bootkit",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence"],
    },
    Technique {
        id: "T1542.004",
        name: "ROMMONkit",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence"],
    },
    Technique {
        id: "T1542.005",
        name: "TFTP Boot",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence"],
    },
    Technique {
        id: "T1543",
        name: "Create or Modify System Process",
        is_subtechnique: false,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1543.001",
        name: "Launch Agent",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1543.002",
        name: "Systemd Service",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1543.003",
        name: "Windows Service",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1543.004",
        name: "Launch Daemon",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1543.005",
        name: "Container Service",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546",
        name: "Event Triggered Execution",
        is_subtechnique: false,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.001",
        name: "Change Default File Association",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.002",
        name: "Screensaver",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.003",
        name: "Windows Management Instrumentation Event Subscription",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.004",
        name: "Unix Shell Configuration Modification",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.005",
        name: "Trap",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.006",
        name: "LC_LOAD_DYLIB Addition",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.007",
        name: "Netsh Helper DLL",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.008",
        name: "Accessibility Features",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.009",
        name: "AppCert DLLs",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.010",
        name: "AppInit DLLs",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.011",
        name: "Application Shimming",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.012",
        name: "Image File Execution Options Injection",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.013",
        name: "PowerShell Profile",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.014",
        name: "Emond",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.015",
        name: "Component Object Model Hijacking",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.016",
        name: "Installer Packages",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1546.017",
        name: "Udev Rules",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547",
        name: "Boot or Logon Autostart Execution",
        is_subtechnique: false,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.001",
        name: "Registry Run Keys / Startup Folder",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.002",
        name: "Authentication Package",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.003",
        name: "Time Providers",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.004",
        name: "Winlogon Helper DLL",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.005",
        name: "Security Support Provider",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.006",
        name: "Kernel Modules and Extensions",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.007",
        name: "Re-opened Applications",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.008",
        name: "LSASS Driver",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.009",
        name: "Shortcut Modification",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.010",
        name: "Port Monitors",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.012",
        name: "Print Processors",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.013",
        name: "XDG Autostart Entries",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.014",
        name: "Active Setup",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1547.015",
        name: "Login Items",
        is_subtechnique: true,
        tactics: &["persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1548",
        name: "Abuse Elevation Control Mechanism",
        is_subtechnique: false,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1548.001",
        name: "Setuid and Setgid",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1548.002",
        name: "Bypass User Account Control",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1548.003",
        name: "Sudo and Sudo Caching",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1548.004",
        name: "Elevated Execution with Prompt",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1548.005",
        name: "Temporary Elevated Cloud Access",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1548.006",
        name: "TCC Manipulation",
        is_subtechnique: true,
        tactics: &["defense-evasion", "privilege-escalation"],
    },
    Technique {
        id: "T1550",
        name: "Use Alternate Authentication Material",
        is_subtechnique: false,
        tactics: &["defense-evasion", "lateral-movement"],
    },
    Technique {
        id: "T1550.001",
        name: "Application Access Token",
        is_subtechnique: true,
        tactics: &["defense-evasion", "lateral-movement"],
    },
    Technique {
        id: "T1550.002",
        name: "Pass the Hash",
        is_subtechnique: true,
        tactics: &["defense-evasion", "lateral-movement"],
    },
    Technique {
        id: "T1550.003",
        name: "Pass the Ticket",
        is_subtechnique: true,
        tactics: &["defense-evasion", "lateral-movement"],
    },
    Technique {
        id: "T1550.004",
        name: "Web Session Cookie",
        is_subtechnique: true,
        tactics: &["defense-evasion", "lateral-movement"],
    },
    Technique {
        id: "T1552",
        name: "Unsecured Credentials",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1552.001",
        name: "Credentials In Files",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1552.002",
        name: "Credentials in Registry",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1552.003",
        name: "Bash History",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1552.004",
        name: "Private Keys",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1552.005",
        name: "Cloud Instance Metadata API",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1552.006",
        name: "Group Policy Preferences",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1552.007",
        name: "Container API",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1552.008",
        name: "Chat Messages",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1553",
        name: "Subvert Trust Controls",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1553.001",
        name: "Gatekeeper Bypass",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1553.002",
        name: "Code Signing",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1553.003",
        name: "SIP and Trust Provider Hijacking",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1553.004",
        name: "Install Root Certificate",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1553.005",
        name: "Mark-of-the-Web Bypass",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1553.006",
        name: "Code Signing Policy Modification",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1554",
        name: "Compromise Host Software Binary",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1555",
        name: "Credentials from Password Stores",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1555.001",
        name: "Keychain",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1555.002",
        name: "Securityd Memory",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1555.003",
        name: "Credentials from Web Browsers",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1555.004",
        name: "Windows Credential Manager",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1555.005",
        name: "Password Managers",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1555.006",
        name: "Cloud Secrets Management Stores",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1556",
        name: "Modify Authentication Process",
        is_subtechnique: false,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.001",
        name: "Domain Controller Authentication",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.002",
        name: "Password Filter DLL",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.003",
        name: "Pluggable Authentication Modules",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.004",
        name: "Network Device Authentication",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.005",
        name: "Reversible Encryption",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.006",
        name: "Multi-Factor Authentication",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.007",
        name: "Hybrid Identity",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.008",
        name: "Network Provider DLL",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1556.009",
        name: "Conditional Access Policies",
        is_subtechnique: true,
        tactics: &["credential-access", "defense-evasion", "persistence"],
    },
    Technique {
        id: "T1557",
        name: "Adversary-in-the-Middle",
        is_subtechnique: false,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1557.001",
        name: "LLMNR/NBT-NS Poisoning and SMB Relay",
        is_subtechnique: true,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1557.002",
        name: "ARP Cache Poisoning",
        is_subtechnique: true,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1557.003",
        name: "DHCP Spoofing",
        is_subtechnique: true,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1557.004",
        name: "Evil Twin",
        is_subtechnique: true,
        tactics: &["collection", "credential-access"],
    },
    Technique {
        id: "T1558",
        name: "Steal or Forge Kerberos Tickets",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1558.001",
        name: "Golden Ticket",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1558.002",
        name: "Silver Ticket",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1558.003",
        name: "Kerberoasting",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1558.004",
        name: "AS-REP Roasting",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1558.005",
        name: "Ccache Files",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1559",
        name: "Inter-Process Communication",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1559.001",
        name: "Component Object Model",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1559.002",
        name: "Dynamic Data Exchange",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1559.003",
        name: "XPC Services",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1560",
        name: "Archive Collected Data",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1560.001",
        name: "Archive via Utility",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1560.002",
        name: "Archive via Library",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1560.003",
        name: "Archive via Custom Method",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1561",
        name: "Disk Wipe",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1561.001",
        name: "Disk Content Wipe",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1561.002",
        name: "Disk Structure Wipe",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1562",
        name: "Impair Defenses",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.001",
        name: "Disable or Modify Tools",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.002",
        name: "Disable Windows Event Logging",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.003",
        name: "Impair Command History Logging",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.004",
        name: "Disable or Modify System Firewall",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.006",
        name: "Indicator Blocking",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.007",
        name: "Disable or Modify Cloud Firewall",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.008",
        name: "Disable or Modify Cloud Logs",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.009",
        name: "Safe Mode Boot",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.010",
        name: "Downgrade Attack",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.011",
        name: "Spoof Security Alerting",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1562.012",
        name: "Disable or Modify Linux Audit System",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1563",
        name: "Remote Service Session Hijacking",
        is_subtechnique: false,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1563.001",
        name: "SSH Hijacking",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1563.002",
        name: "RDP Hijacking",
        is_subtechnique: true,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1564",
        name: "Hide Artifacts",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.001",
        name: "Hidden Files and Directories",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.002",
        name: "Hidden Users",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.003",
        name: "Hidden Window",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.004",
        name: "NTFS File Attributes",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.005",
        name: "Hidden File System",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.006",
        name: "Run Virtual Instance",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.007",
        name: "VBA Stomping",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.008",
        name: "Email Hiding Rules",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.009",
        name: "Resource Forking",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.010",
        name: "Process Argument Spoofing",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.011",
        name: "Ignore Process Interrupts",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.012",
        name: "File/Path Exclusions",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.013",
        name: "Bind Mounts",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1564.014",
        name: "Extended Attributes",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1565",
        name: "Data Manipulation",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1565.001",
        name: "Stored Data Manipulation",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1565.002",
        name: "Transmitted Data Manipulation",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1565.003",
        name: "Runtime Data Manipulation",
        is_subtechnique: true,
        tactics: &["impact"],
    },
    Technique {
        id: "T1566",
        name: "Phishing",
        is_subtechnique: false,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1566.001",
        name: "Spearphishing Attachment",
        is_subtechnique: true,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1566.002",
        name: "Spearphishing Link",
        is_subtechnique: true,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1566.003",
        name: "Spearphishing via Service",
        is_subtechnique: true,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1566.004",
        name: "Spearphishing Voice",
        is_subtechnique: true,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1567",
        name: "Exfiltration Over Web Service",
        is_subtechnique: false,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1567.001",
        name: "Exfiltration to Code Repository",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1567.002",
        name: "Exfiltration to Cloud Storage",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1567.003",
        name: "Exfiltration to Text Storage Sites",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1567.004",
        name: "Exfiltration Over Webhook",
        is_subtechnique: true,
        tactics: &["exfiltration"],
    },
    Technique {
        id: "T1568",
        name: "Dynamic Resolution",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1568.001",
        name: "Fast Flux DNS",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1568.002",
        name: "Domain Generation Algorithms",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1568.003",
        name: "DNS Calculation",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1569",
        name: "System Services",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1569.001",
        name: "Launchctl",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1569.002",
        name: "Service Execution",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1569.003",
        name: "Systemctl",
        is_subtechnique: true,
        tactics: &["execution"],
    },
    Technique {
        id: "T1570",
        name: "Lateral Tool Transfer",
        is_subtechnique: false,
        tactics: &["lateral-movement"],
    },
    Technique {
        id: "T1571",
        name: "Non-Standard Port",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1572",
        name: "Protocol Tunneling",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1573",
        name: "Encrypted Channel",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1573.001",
        name: "Symmetric Cryptography",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1573.002",
        name: "Asymmetric Cryptography",
        is_subtechnique: true,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1574",
        name: "Hijack Execution Flow",
        is_subtechnique: false,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.001",
        name: "DLL",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.004",
        name: "Dylib Hijacking",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.005",
        name: "Executable Installer File Permissions Weakness",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.006",
        name: "Dynamic Linker Hijacking",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.007",
        name: "Path Interception by PATH Environment Variable",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.008",
        name: "Path Interception by Search Order Hijacking",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.009",
        name: "Path Interception by Unquoted Path",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.010",
        name: "Services File Permissions Weakness",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.011",
        name: "Services Registry Permissions Weakness",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.012",
        name: "COR_PROFILER",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.013",
        name: "KernelCallbackTable",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1574.014",
        name: "AppDomainManager",
        is_subtechnique: true,
        tactics: &["defense-evasion", "persistence", "privilege-escalation"],
    },
    Technique {
        id: "T1578",
        name: "Modify Cloud Compute Infrastructure",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1578.001",
        name: "Create Snapshot",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1578.002",
        name: "Create Cloud Instance",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1578.003",
        name: "Delete Cloud Instance",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1578.004",
        name: "Revert Cloud Instance",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1578.005",
        name: "Modify Cloud Compute Configurations",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1580",
        name: "Cloud Infrastructure Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1583",
        name: "Acquire Infrastructure",
        is_subtechnique: false,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1583.001",
        name: "Domains",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1583.002",
        name: "DNS Server",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1583.003",
        name: "Virtual Private Server",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1583.004",
        name: "Server",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1583.005",
        name: "Botnet",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1583.006",
        name: "Web Services",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1583.007",
        name: "Serverless",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1583.008",
        name: "Malvertising",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584",
        name: "Compromise Infrastructure",
        is_subtechnique: false,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584.001",
        name: "Domains",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584.002",
        name: "DNS Server",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584.003",
        name: "Virtual Private Server",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584.004",
        name: "Server",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584.005",
        name: "Botnet",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584.006",
        name: "Web Services",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584.007",
        name: "Serverless",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1584.008",
        name: "Network Devices",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1585",
        name: "Establish Accounts",
        is_subtechnique: false,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1585.001",
        name: "Social Media Accounts",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1585.002",
        name: "Email Accounts",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1585.003",
        name: "Cloud Accounts",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1586",
        name: "Compromise Accounts",
        is_subtechnique: false,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1586.001",
        name: "Social Media Accounts",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1586.002",
        name: "Email Accounts",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1586.003",
        name: "Cloud Accounts",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1587",
        name: "Develop Capabilities",
        is_subtechnique: false,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1587.001",
        name: "Malware",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1587.002",
        name: "Code Signing Certificates",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1587.003",
        name: "Digital Certificates",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1587.004",
        name: "Exploits",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1588",
        name: "Obtain Capabilities",
        is_subtechnique: false,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1588.001",
        name: "Malware",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1588.002",
        name: "Tool",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1588.003",
        name: "Code Signing Certificates",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1588.004",
        name: "Digital Certificates",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1588.005",
        name: "Exploits",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1588.006",
        name: "Vulnerabilities",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1588.007",
        name: "Artificial Intelligence",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1589",
        name: "Gather Victim Identity Information",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1589.001",
        name: "Credentials",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1589.002",
        name: "Email Addresses",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1589.003",
        name: "Employee Names",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1590",
        name: "Gather Victim Network Information",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1590.001",
        name: "Domain Properties",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1590.002",
        name: "DNS",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1590.003",
        name: "Network Trust Dependencies",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1590.004",
        name: "Network Topology",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1590.005",
        name: "IP Addresses",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1590.006",
        name: "Network Security Appliances",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1591",
        name: "Gather Victim Org Information",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1591.001",
        name: "Determine Physical Locations",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1591.002",
        name: "Business Relationships",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1591.003",
        name: "Identify Business Tempo",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1591.004",
        name: "Identify Roles",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1592",
        name: "Gather Victim Host Information",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1592.001",
        name: "Hardware",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1592.002",
        name: "Software",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1592.003",
        name: "Firmware",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1592.004",
        name: "Client Configurations",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1593",
        name: "Search Open Websites/Domains",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1593.001",
        name: "Social Media",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1593.002",
        name: "Search Engines",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1593.003",
        name: "Code Repositories",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1594",
        name: "Search Victim-Owned Websites",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1595",
        name: "Active Scanning",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1595.001",
        name: "Scanning IP Blocks",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1595.002",
        name: "Vulnerability Scanning",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1595.003",
        name: "Wordlist Scanning",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1596",
        name: "Search Open Technical Databases",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1596.001",
        name: "DNS/Passive DNS",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1596.002",
        name: "WHOIS",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1596.003",
        name: "Digital Certificates",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1596.004",
        name: "CDNs",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1596.005",
        name: "Scan Databases",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1597",
        name: "Search Closed Sources",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1597.001",
        name: "Threat Intel Vendors",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1597.002",
        name: "Purchase Technical Data",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1598",
        name: "Phishing for Information",
        is_subtechnique: false,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1598.001",
        name: "Spearphishing Service",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1598.002",
        name: "Spearphishing Attachment",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1598.003",
        name: "Spearphishing Link",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1598.004",
        name: "Spearphishing Voice",
        is_subtechnique: true,
        tactics: &["reconnaissance"],
    },
    Technique {
        id: "T1599",
        name: "Network Boundary Bridging",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1599.001",
        name: "Network Address Translation Traversal",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1600",
        name: "Weaken Encryption",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1600.001",
        name: "Reduce Key Space",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1600.002",
        name: "Disable Crypto Hardware",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1601",
        name: "Modify System Image",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1601.001",
        name: "Patch System Image",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1601.002",
        name: "Downgrade System Image",
        is_subtechnique: true,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1602",
        name: "Data from Configuration Repository",
        is_subtechnique: false,
        tactics: &["collection"],
    },
    Technique {
        id: "T1602.001",
        name: "SNMP (MIB Dump)",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1602.002",
        name: "Network Device Configuration Dump",
        is_subtechnique: true,
        tactics: &["collection"],
    },
    Technique {
        id: "T1606",
        name: "Forge Web Credentials",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1606.001",
        name: "Web Cookies",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1606.002",
        name: "SAML Tokens",
        is_subtechnique: true,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1608",
        name: "Stage Capabilities",
        is_subtechnique: false,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1608.001",
        name: "Upload Malware",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1608.002",
        name: "Upload Tool",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1608.003",
        name: "Install Digital Certificate",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1608.004",
        name: "Drive-by Target",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1608.005",
        name: "Link Target",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1608.006",
        name: "SEO Poisoning",
        is_subtechnique: true,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1609",
        name: "Container Administration Command",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1610",
        name: "Deploy Container",
        is_subtechnique: false,
        tactics: &["defense-evasion", "execution"],
    },
    Technique {
        id: "T1611",
        name: "Escape to Host",
        is_subtechnique: false,
        tactics: &["privilege-escalation"],
    },
    Technique {
        id: "T1612",
        name: "Build Image on Host",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1613",
        name: "Container and Resource Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1614",
        name: "System Location Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1614.001",
        name: "System Language Discovery",
        is_subtechnique: true,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1615",
        name: "Group Policy Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1619",
        name: "Cloud Storage Object Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1620",
        name: "Reflective Code Loading",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1621",
        name: "Multi-Factor Authentication Request Generation",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1622",
        name: "Debugger Evasion",
        is_subtechnique: false,
        tactics: &["defense-evasion", "discovery"],
    },
    Technique {
        id: "T1647",
        name: "Plist File Modification",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1648",
        name: "Serverless Execution",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1649",
        name: "Steal or Forge Authentication Certificates",
        is_subtechnique: false,
        tactics: &["credential-access"],
    },
    Technique {
        id: "T1650",
        name: "Acquire Access",
        is_subtechnique: false,
        tactics: &["resource-development"],
    },
    Technique {
        id: "T1651",
        name: "Cloud Administration Command",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1652",
        name: "Device Driver Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1653",
        name: "Power Settings",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1654",
        name: "Log Enumeration",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1656",
        name: "Impersonation",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1657",
        name: "Financial Theft",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1659",
        name: "Content Injection",
        is_subtechnique: false,
        tactics: &["command-and-control", "initial-access"],
    },
    Technique {
        id: "T1665",
        name: "Hide Infrastructure",
        is_subtechnique: false,
        tactics: &["command-and-control"],
    },
    Technique {
        id: "T1666",
        name: "Modify Cloud Resource Hierarchy",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1667",
        name: "Email Bombing",
        is_subtechnique: false,
        tactics: &["impact"],
    },
    Technique {
        id: "T1668",
        name: "Exclusive Control",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1669",
        name: "Wi-Fi Networks",
        is_subtechnique: false,
        tactics: &["initial-access"],
    },
    Technique {
        id: "T1671",
        name: "Cloud Application Integration",
        is_subtechnique: false,
        tactics: &["persistence"],
    },
    Technique {
        id: "T1672",
        name: "Email Spoofing",
        is_subtechnique: false,
        tactics: &["defense-evasion"],
    },
    Technique {
        id: "T1673",
        name: "Virtual Machine Discovery",
        is_subtechnique: false,
        tactics: &["discovery"],
    },
    Technique {
        id: "T1674",
        name: "Input Injection",
        is_subtechnique: false,
        tactics: &["execution"],
    },
    Technique {
        id: "T1675",
        name: "ESXi Administration Command",
        is_subtechnique: false,
        tactics: &["execution"],
    },
];

/// The catalogued technique with this ID, if any. Searches the entire Enterprise
/// catalogue, so any `Tnnnn[.nnn]` the tool emits resolves to its canonical name.
#[must_use]
pub fn technique(id: &str) -> Option<&'static Technique> {
    ENTERPRISE.iter().find(|t| t.id == id)
}

/// The catalogued tactic with this ID (`TA0043`) or `shortname` (`reconnaissance`).
#[must_use]
pub fn tactic(id_or_shortname: &str) -> Option<&'static Tactic> {
    TACTICS
        .iter()
        .find(|t| t.id == id_or_shortname || t.shortname == id_or_shortname)
}

/// Every technique belonging to the tactic named by `shortname` (e.g.
/// `reconnaissance`), in the catalogue's sorted order. Empty for an unknown
/// shortname.
#[must_use]
pub fn techniques_for_tactic(shortname: &str) -> Vec<&'static Technique> {
    ENTERPRISE
        .iter()
        .filter(|t| t.tactics.contains(&shortname))
        .collect()
}

/// The full Reconnaissance tactic (TA0043) — the slice HSE performs collection
/// for. Derived from the catalogue so it can never drift from the framework data.
/// A drift-guard test pins that this is exactly the complete TA0043 tactic.
#[must_use]
pub fn reconnaissance() -> Vec<&'static Technique> {
    techniques_for_tactic("reconnaissance")
}

/// The Reconnaissance techniques for which `is_covered` returns `false` — the
/// honest coverage *gaps* for a coverage set (typically the union of every
/// module's [`crate::core::module::Module::attack_techniques`]), in sorted order.
/// Computed against the Reconnaissance tactic alone: that is the tactic HSE
/// claims, so a gap here names exactly which collection HSE performs none of,
/// instead of implying total coverage of a tactic — or of the framework.
#[must_use]
pub fn uncovered(is_covered: impl Fn(&str) -> bool) -> Vec<&'static Technique> {
    reconnaissance()
        .into_iter()
        .filter(|t| !is_covered(t.id))
        .collect()
}

/// The ATT&CK Reconnaissance technique IDs a module's functional
/// [`ModuleCategory`] implements — the **default** mapping every module inherits
/// (a module whose category is too coarse, e.g. an active scanner sitting in
/// `Infrastructure`, overrides [`crate::core::module::Module::attack_techniques`]
/// directly). Category-level is the right granularity for the default because
/// the category already encodes what kind of collection the module performs.
#[must_use]
pub fn techniques_for_category(cat: ModuleCategory) -> &'static [&'static str] {
    match cat {
        // DNS / cert / WHOIS recon is the canonical "search open technical
        // databases" + "gather network information" cluster.
        ModuleCategory::DnsRecon => &[
            "T1590.001",
            "T1590.002",
            "T1596.001",
            "T1596.002",
            "T1596.003",
        ],
        // Breach corpora expose leaked credentials and email addresses.
        ModuleCategory::Breach => &["T1589.001", "T1589.002"],
        // IP/ASN/Shodan-style infra intel: network IPs via open scan databases.
        ModuleCategory::Infrastructure => &["T1590.005", "T1596.005"],
        // Search-engine scraping.
        ModuleCategory::Search => &["T1593.002"],
        // Social profiles + the employee/handle names they reveal.
        ModuleCategory::Social => &["T1593.001", "T1589.003"],
        ModuleCategory::Email => &["T1589.002"],
        // No phone sub-technique exists; phone metadata is victim identity info.
        ModuleCategory::Phone => &["T1589"],
        // Company registry / directorship / role intel.
        ModuleCategory::Corporate => &["T1591.002", "T1591.004"],
        // Malware/C2/abuse lists are bought-or-free threat-intel vendor data.
        ModuleCategory::Threat => &["T1597.001"],
        // Local device sensors gather host information.
        ModuleCategory::Sensor => &["T1592"],
        // People-centric enrichment: employee names + their organisational role.
        ModuleCategory::People => &["T1589.003", "T1591.004"],
        // Site crawling / fingerprinting victim-owned sites and their software.
        ModuleCategory::Web => &["T1594", "T1592.002"],
        // Geolocation / address resolution → physical locations.
        ModuleCategory::Geo => &["T1591.001"],
        // Uncategorised — no claimed ATT&CK mapping.
        ModuleCategory::Other => &[],
    }
}

/// One exercised technique in a [`Coverage`] rollup: the catalogued technique
/// plus the number of scan entities collected via it.
#[derive(Debug, Clone, Serialize)]
pub struct CoveredTechnique {
    /// The catalogued technique (`id` + `name`), flattened into the object.
    #[serde(flatten)]
    pub technique: Technique,
    /// How many of the scan's entities carry this technique's `attack:<id>` tag.
    pub entity_count: usize,
}

/// A scan's MITRE ATT&CK **Reconnaissance** (TA0043) coverage: the techniques it
/// exercised (with entity counts) and the honest uncovered gaps, both in the
/// catalogue's sorted order. Built by [`coverage`] from the `attack:<id>` tags
/// the engine stamps on every admitted entity, and serialised straight to the
/// `/scans/{id}/attack` API surface.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// Always [`TACTIC_ID`] — the one Enterprise tactic HSE honestly performs.
    pub tactic_id: &'static str,
    /// Always [`TACTIC_NAME`].
    pub tactic_name: &'static str,
    /// Techniques the scan actually exercised, catalogue-sorted.
    pub covered: Vec<CoveredTechnique>,
    /// Catalogued TA0043 techniques the scan performed no collection for — the
    /// honest gaps, straight from [`uncovered`].
    pub uncovered: Vec<&'static Technique>,
    /// `covered.len() / RECONNAISSANCE.len()`, in `0.0..=1.0`.
    pub coverage_fraction: f64,
}

/// Roll a scan's exercised technique IDs (with per-technique entity counts —
/// typically the `attack:<id>` tags counted across the scan's entities) up into
/// a [`Coverage`]. Unknown IDs are ignored (the drift guard keeps them from ever
/// being emitted). Covered techniques and gaps come back catalogue-sorted, so
/// the rollup is deterministic regardless of entity iteration order.
#[must_use]
pub fn coverage(exercised: &std::collections::BTreeMap<String, usize>) -> Coverage {
    let covered: Vec<CoveredTechnique> = RECONNAISSANCE
        .iter()
        .filter_map(|t| {
            exercised.get(t.id).map(|&entity_count| CoveredTechnique {
                technique: *t,
                entity_count,
            })
        })
        .collect();
    let gaps = uncovered(|id| exercised.contains_key(id));
    #[allow(clippy::cast_precision_loss)]
    let coverage_fraction = if RECONNAISSANCE.is_empty() {
        0.0
    } else {
        covered.len() as f64 / RECONNAISSANCE.len() as f64
    };
    Coverage {
        tactic_id: TACTIC_ID,
        tactic_name: TACTIC_NAME,
        covered,
        uncovered: gaps,
        coverage_fraction,
    }
}

/// Serialise a [`Coverage`] as a MITRE ATT&CK **Navigator layer** — the standard
/// JSON the official [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
/// renders — so a scan's Reconnaissance coverage drops straight into MITRE's own
/// visualisation instead of living only in HSE's tags. Each exercised technique
/// carries a `score` equal to its entity count (the Navigator heat-map then shows
/// collection *intensity*); every uncovered TA0043 technique is emitted disabled
/// with `score: 0`, so the layer is an honest picture of exactly what HSE
/// collected and what it did not. `scan_label` names the source scan.
#[must_use]
pub fn navigator_layer(coverage: &Coverage, scan_label: &str) -> serde_json::Value {
    let max_score = coverage
        .covered
        .iter()
        .map(|c| c.entity_count)
        .max()
        .unwrap_or(0)
        .max(1);
    let mut techniques: Vec<serde_json::Value> = coverage
        .covered
        .iter()
        .map(|c| {
            serde_json::json!({
                "techniqueID": c.technique.id,
                "tactic": "reconnaissance",
                "score": c.entity_count,
                "enabled": true,
                "comment": c.technique.name,
            })
        })
        .collect();
    for t in &coverage.uncovered {
        techniques.push(serde_json::json!({
            "techniqueID": t.id,
            "tactic": "reconnaissance",
            "score": 0,
            "enabled": false,
            "comment": t.name,
        }));
    }
    serde_json::json!({
        "name": format!("HSE — {scan_label} (Reconnaissance coverage)"),
        "versions": { "attack": "16", "navigator": "5.1.0", "layer": "4.5" },
        "domain": "enterprise-attack",
        "description": "MITRE ATT&CK Reconnaissance (TA0043) coverage produced by \
                        Huntsman Search Engine. score = entities collected via each \
                        technique; disabled techniques are honest gaps (no collection \
                        performed). Scoped to TA0043 — a passive OSINT collector \
                        performs no post-compromise tactic.",
        "sorting": 3,
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
            "minValue": 0,
            "maxValue": max_score
        },
        "legendItems": [],
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
