//! Android binary XML (AXML), as `aapt`/`aapt2` compile `AndroidManifest.xml`: the string pool,
//! the resource-ID map and the start-element chunks, read with every offset bounds-checked.
//!
//! An attribute is named the way the platform resolves it: by the framework resource ID its name
//! maps to when the map has one (the IDs below are AOSP's `R.attr` constants), else by its name
//! in the string pool. So a manifest whose attribute name strings were blanked or renamed, a
//! known obfuscation, still reads as Android reads it. Only the manifest facts an investigator
//! pivots on are kept; nothing is executed or resolved against the app's own resources.

use std::collections::BTreeSet;

use serde::Serialize;

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const UTF8_FLAG: u32 = 0x0100;
const NO_INDEX: u32 = 0xffff_ffff;
/// Element nesting deeper than any manifest needs is refused rather than tracked.
const MAX_DEPTH: usize = 64;
const MAX_STRINGS: usize = 65_536;
/// Each list is capped; the count of what did not fit is reported beside it.
const MAX_LISTED: usize = 256;

const TYPE_REFERENCE: u8 = 0x01;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

/// The framework attributes read here, by their `android.R.attr` resource IDs.
const ATTRIBUTE_IDS: [(u32, &str); 22] = [
    (0x0101_0003, "name"),
    (0x0101_000e, "enabled"),
    (0x0101_000f, "debuggable"),
    (0x0101_0010, "exported"),
    (0x0101_0018, "authorities"),
    (0x0101_0027, "scheme"),
    (0x0101_0028, "host"),
    (0x0101_0029, "port"),
    (0x0101_002a, "path"),
    (0x0101_002b, "pathPrefix"),
    (0x0101_002c, "pathPattern"),
    (0x0101_000b, "sharedUserId"),
    (0x0101_020c, "minSdkVersion"),
    (0x0101_021b, "versionCode"),
    (0x0101_021c, "versionName"),
    (0x0101_0270, "targetSdkVersion"),
    (0x0101_0271, "maxSdkVersion"),
    (0x0101_0272, "testOnly"),
    (0x0101_0280, "allowBackup"),
    (0x0101_04ec, "usesCleartextTraffic"),
    (0x0101_04ee, "autoVerify"),
    (0x0101_0527, "networkSecurityConfig"),
];

/// How a component is reachable from other apps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// `android:exported="true"`.
    Exported,
    /// No `android:exported`, but an intent filter: other apps can start it on Android 11 and
    /// earlier, and an app targeting Android 12 must not ship it this way.
    ImplicitByIntentFilter,
}

/// A component other apps can reach, as the manifest declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Component {
    /// `activity`, `activity-alias`, `service`, `receiver` or `provider`.
    pub kind: String,
    pub name: String,
    pub exposure: Exposure,
}

/// A single intent-filter declaration with its action/category/data constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntentFilterDef {
    /// The component this filter applies to (e.g., "com.example.MainActivity").
    pub component: String,
    /// Component kind: "activity", "service", "`broadcast_receiver`", or "provider".
    pub component_kind: String,
    /// Intent actions this component handles (e.g., "android.intent.action.VIEW").
    pub actions: Vec<String>,
    /// Intent categories this component handles (e.g., "android.intent.category.LAUNCHER").
    pub categories: Vec<String>,
    /// Data schemes this filter accepts (e.g., "http", "https", "custom").
    pub schemes: Vec<String>,
    /// Data hosts this filter accepts (e.g., "example.com", "*.example.com").
    pub hosts: Vec<String>,
}

/// The investigator-relevant facts a binary `AndroidManifest.xml` declares. Every value is the
/// manifest's own claim, as the developer (or whoever rebuilt the APK) wrote it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub package: Option<String>,
    /// The application label when the manifest gives it inline as a literal string.
    pub label: Option<String>,
    /// The resource id the application label references (`android:label="@0x…"`), to resolve from
    /// `resources.arsc`; the displayed app name is almost always a reference, not a literal.
    pub label_resource_id: Option<u32>,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub shared_user_id: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub permissions: Vec<String>,
    pub permissions_omitted: usize,
    pub debuggable: Option<bool>,
    pub test_only: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: bool,
    /// Exact resource reference from the manifest; a declaration alone is not a decoded policy.
    pub network_security_config_resource_id: Option<u32>,
    pub components: usize,
    pub reachable_components: Vec<Component>,
    pub reachable_components_omitted: usize,
    pub deep_link_schemes: Vec<String>,
    pub deep_link_hosts: Vec<String>,
    pub deep_link_hosts_omitted: usize,
    /// Whether an intent filter asks Android to verify its hosts as App Links (`autoVerify`).
    pub app_links_auto_verify: bool,
    pub provider_authorities: Vec<String>,
    /// Authority claims tied to explicitly exported, enabled providers (bounded, not verified access).
    pub explicitly_exported_provider_authorities: Vec<String>,
    /// Intent filters extracted from manifest, capped at `MAX_LISTED`.
    pub intent_filters: Vec<IntentFilterDef>,
    /// Count of intent filters omitted when list exceeds capacity.
    pub intent_filters_omitted: usize,
}

fn le16(data: &[u8], at: usize) -> Option<u16> {
    let field = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

fn le32(data: &[u8], at: usize) -> Option<u32> {
    let field = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn index(value: u32) -> Option<usize> {
    usize::try_from(value).ok()
}

/// A chunk's type, header size and whole size, refused when it does not fit inside `limit`.
fn chunk(data: &[u8], at: usize, limit: usize) -> Result<(u16, usize, usize), String> {
    let kind = le16(data, at).ok_or("truncated chunk header")?;
    let header = usize::from(le16(data, at + 2).ok_or("truncated chunk header")?);
    let size = le32(data, at + 4)
        .and_then(index)
        .ok_or("truncated chunk header")?;
    if header < 8 || size < header || at.checked_add(size).is_none_or(|end| end > limit) {
        return Err(format!("chunk 0x{kind:04x} at {at} has an invalid size"));
    }
    Ok((kind, header, size))
}

/// The length prefix of a pool string: one unit, or two with the high bit of the first set.
fn utf8_length(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *data.get(at)?;
    if first & 0x80 == 0 {
        return Some((usize::from(first), 1));
    }
    let second = *data.get(at + 1)?;
    Some(((usize::from(first & 0x7f) << 8) | usize::from(second), 2))
}

fn utf16_length(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = le16(data, at)?;
    if first & 0x8000 == 0 {
        return Some((usize::from(first), 2));
    }
    let second = le16(data, at + 2)?;
    Some(((usize::from(first & 0x7fff) << 16) | usize::from(second), 4))
}

fn pool_string(data: &[u8], at: usize, utf8: bool) -> Option<String> {
    if utf8 {
        // A UTF-16 length, then the UTF-8 byte length the bytes are counted by.
        let (_, skip) = utf8_length(data, at)?;
        let (bytes, more) = utf8_length(data, at + skip)?;
        let start = at + skip + more;
        let raw = data.get(start..start.checked_add(bytes)?)?;
        Some(String::from_utf8_lossy(raw).into_owned())
    } else {
        let (units, skip) = utf16_length(data, at)?;
        let start = at + skip;
        let raw = data.get(start..start.checked_add(units.checked_mul(2)?)?)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }
}

/// Every string of the pool chunk at `at`; a string whose offset is out of range is empty.
fn string_pool(data: &[u8], at: usize, header: usize, size: usize) -> Result<Vec<String>, String> {
    let count = le32(data, at + 8)
        .and_then(index)
        .ok_or("truncated string pool")?;
    let flags = le32(data, at + 16).ok_or("truncated string pool")?;
    let strings_start = le32(data, at + 20)
        .and_then(index)
        .ok_or("truncated string pool")?;
    if count > MAX_STRINGS {
        return Err(format!("string pool holds over {MAX_STRINGS} strings"));
    }
    let chunk_end = at + size;
    let utf8 = flags & UTF8_FLAG != 0;
    let mut strings = Vec::with_capacity(count);
    for i in 0..count {
        let offset = le32(data, at + header + i * 4)
            .and_then(index)
            .ok_or("truncated string pool offsets")?;
        let text = at
            .checked_add(strings_start)
            .and_then(|base| base.checked_add(offset))
            .filter(|&start| start < chunk_end)
            .and_then(|start| pool_string(&data[..chunk_end], start, utf8))
            .unwrap_or_default();
        strings.push(text);
    }
    Ok(strings)
}

/// One attribute as Android reads it: its resolved name and its value as text.
struct Attribute {
    name: String,
    value: String,
    boolean: Option<bool>,
    /// The raw resource id when the attribute is a reference (`android:label="@0x…"`), for a later
    /// `resources.arsc` lookup; `None` for an inline value.
    reference: Option<u32>,
}

struct Document {
    strings: Vec<String>,
    resource_ids: Vec<u32>,
}

impl Document {
    fn string(&self, index: u32) -> Option<&str> {
        self.strings
            .get(usize::try_from(index).ok()?)
            .map(String::as_str)
    }

    fn attribute_name(&self, name: u32) -> String {
        let by_id = usize::try_from(name)
            .ok()
            .and_then(|i| self.resource_ids.get(i))
            .and_then(|id| ATTRIBUTE_IDS.iter().find(|(known, _)| known == id))
            .map(|(_, name)| *name);
        by_id.map_or_else(
            || self.string(name).unwrap_or_default().to_owned(),
            str::to_owned,
        )
    }

    fn attributes(&self, data: &[u8], node: usize, header: usize) -> Option<Vec<Attribute>> {
        let ext = node + header;
        let start = usize::from(le16(data, ext + 8)?);
        let width = usize::from(le16(data, ext + 10)?);
        let count = usize::from(le16(data, ext + 12)?);
        if width < 20 {
            return None;
        }
        let mut attributes = Vec::with_capacity(count);
        for i in 0..count {
            let at = ext.checked_add(start)?.checked_add(i.checked_mul(width)?)?;
            let name = self.attribute_name(le32(data, at + 4)?);
            let raw = le32(data, at + 8)?;
            let kind = *data.get(at + 15)?;
            let value = le32(data, at + 16)?;
            let boolean = (kind == TYPE_INT_BOOLEAN).then_some(value != 0);
            let text = if raw == NO_INDEX {
                match kind {
                    TYPE_STRING => self.string(value).unwrap_or_default().to_owned(),
                    TYPE_INT_DEC => i32::from_le_bytes(value.to_le_bytes()).to_string(),
                    TYPE_INT_BOOLEAN => (value != 0).to_string(),
                    TYPE_REFERENCE => format!("@0x{value:08x}"),
                    TYPE_INT_HEX => format!("0x{value:x}"),
                    _ => format!("0x{value:08x}"),
                }
            } else {
                self.string(raw).unwrap_or_default().to_owned()
            };
            let reference = (kind == TYPE_REFERENCE && raw == NO_INDEX).then_some(value);
            attributes.push(Attribute {
                name,
                value: text,
                boolean,
                reference,
            });
        }
        Some(attributes)
    }
}

fn value<'a>(attributes: &'a [Attribute], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.value.as_str())
}

fn reference(attributes: &[Attribute], name: &str) -> Option<u32> {
    attributes
        .iter()
        .find(|attribute| attribute.name == name)
        .and_then(|attribute| attribute.reference)
}

fn flag(attributes: &[Attribute], name: &str) -> Option<bool> {
    let attribute = attributes.iter().find(|attribute| attribute.name == name)?;
    attribute
        .boolean
        .or_else(|| attribute.value.parse::<bool>().ok())
}

fn push_capped(
    list: &mut Vec<String>,
    omitted: &mut usize,
    seen: &mut BTreeSet<String>,
    item: &str,
) {
    if item.is_empty() || !seen.insert(item.to_owned()) {
        return;
    }
    if list.len() < MAX_LISTED {
        list.push(item.to_owned());
    } else {
        *omitted += 1;
    }
}

const COMPONENTS: [&str; 5] = [
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
];

/// A component element being read: what it declared and whether an intent filter followed.
struct Open {
    kind: String,
    name: String,
    exported: Option<bool>,
    filtered: bool,
    enabled: Option<bool>,
    authorities: Vec<String>,
}

/// An intent-filter being parsed: its actions, categories, and data constraints.
struct IntentFilterState {
    actions: Vec<String>,
    categories: Vec<String>,
    schemes: Vec<String>,
    hosts: Vec<String>,
}

#[derive(Default)]
struct Reader {
    manifest: Manifest,
    permissions: BTreeSet<String>,
    hosts: BTreeSet<String>,
    schemes: BTreeSet<String>,
    authorities: BTreeSet<String>,
    application_enabled: Option<bool>,
    open: Option<Open>,
    intent_filter: Option<IntentFilterState>,
    seen_filters: BTreeSet<String>,
}

/// Preserve each provider's authority claims separately from the manifest-wide inventory.
fn collect_provider_authorities(
    manifest: &mut Manifest,
    seen: &mut BTreeSet<String>,
    attributes: &[Attribute],
) -> Vec<String> {
    let mut own_authorities: Vec<String> = Vec::new();
    for authority in value(attributes, "authorities")
        .unwrap_or_default()
        .split(';')
    {
        let authority = authority.trim();
        let mut omitted = 0;
        push_capped(
            &mut manifest.provider_authorities,
            &mut omitted,
            seen,
            authority,
        );
        if !authority.is_empty()
            && own_authorities.len() < MAX_LISTED
            && !own_authorities
                .iter()
                .any(|known| known.as_str() == authority)
        {
            own_authorities.push(authority.to_owned());
        }
    }
    own_authorities
}

impl Reader {
    #[allow(clippy::too_many_lines)]
    fn start(&mut self, element: &str, parent: Option<&str>, attributes: &[Attribute]) {
        let component = COMPONENTS.contains(&element) && parent == Some("application");
        if component {
            self.close_component();
        }
        let manifest = &mut self.manifest;
        match element {
            "manifest" => {
                manifest.package = value(attributes, "package").map(str::to_owned);
                manifest.version_code = value(attributes, "versionCode").map(str::to_owned);
                manifest.version_name = value(attributes, "versionName").map(str::to_owned);
                manifest.shared_user_id = value(attributes, "sharedUserId").map(str::to_owned);
            }
            "uses-sdk" => {
                manifest.min_sdk = value(attributes, "minSdkVersion").map(str::to_owned);
                manifest.target_sdk = value(attributes, "targetSdkVersion").map(str::to_owned);
            }
            "uses-permission" | "uses-permission-sdk-23" => {
                if let Some(name) = value(attributes, "name") {
                    push_capped(
                        &mut manifest.permissions,
                        &mut manifest.permissions_omitted,
                        &mut self.permissions,
                        name,
                    );
                }
            }
            "application" => {
                self.application_enabled = flag(attributes, "enabled");
                manifest.label_resource_id = reference(attributes, "label");
                if manifest.label_resource_id.is_none() {
                    // A literal, non-reference label is the displayed name as-is.
                    manifest.label = value(attributes, "label")
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned);
                }
                manifest.debuggable = flag(attributes, "debuggable");
                manifest.test_only = flag(attributes, "testOnly");
                manifest.allow_backup = flag(attributes, "allowBackup");
                manifest.uses_cleartext_traffic = flag(attributes, "usesCleartextTraffic");
                manifest.network_security_config =
                    value(attributes, "networkSecurityConfig").is_some();
                manifest.network_security_config_resource_id =
                    reference(attributes, "networkSecurityConfig");
            }
            kind if component => {
                manifest.components += 1;
                let own_authorities = if kind == "provider" {
                    collect_provider_authorities(manifest, &mut self.authorities, attributes)
                } else {
                    Vec::new()
                };
                self.open = Some(Open {
                    kind: kind.to_owned(),
                    name: value(attributes, "name").unwrap_or_default().to_owned(),
                    exported: flag(attributes, "exported"),
                    filtered: false,
                    enabled: flag(attributes, "enabled"),
                    authorities: own_authorities,
                });
            }
            "intent-filter" => {
                if let Some(open) = self.open.as_mut() {
                    open.filtered = true;
                }
                if flag(attributes, "autoVerify") == Some(true) {
                    manifest.app_links_auto_verify = true;
                }
                self.intent_filter = Some(IntentFilterState {
                    actions: Vec::new(),
                    categories: Vec::new(),
                    schemes: Vec::new(),
                    hosts: Vec::new(),
                });
            }
            "action" if parent == Some("intent-filter") => {
                if let Some(filter) = self.intent_filter.as_mut() {
                    if let Some(name) = value(attributes, "name") {
                        filter.actions.push(name.to_owned());
                    }
                }
            }
            "category" if parent == Some("intent-filter") => {
                if let Some(filter) = self.intent_filter.as_mut() {
                    if let Some(name) = value(attributes, "name") {
                        filter.categories.push(name.to_owned());
                    }
                }
            }
            "data" if parent == Some("intent-filter") => {
                if let Some(scheme) = value(attributes, "scheme") {
                    let mut omitted = 0;
                    push_capped(
                        &mut manifest.deep_link_schemes,
                        &mut omitted,
                        &mut self.schemes,
                        &scheme.to_ascii_lowercase(),
                    );
                    if let Some(filter) = self.intent_filter.as_mut() {
                        filter.schemes.push(scheme.to_ascii_lowercase());
                    }
                }
                if let Some(host) = value(attributes, "host") {
                    push_capped(
                        &mut manifest.deep_link_hosts,
                        &mut manifest.deep_link_hosts_omitted,
                        &mut self.hosts,
                        &host.to_ascii_lowercase(),
                    );
                    if let Some(filter) = self.intent_filter.as_mut() {
                        filter.hosts.push(host.to_ascii_lowercase());
                    }
                }
            }
            _ => {}
        }
    }

    /// Finalizes the current intent-filter and stores it in the manifest.
    fn close_intent_filter(&mut self) {
        let Some(filter) = self.intent_filter.take() else {
            return;
        };
        let Some(open) = self.open.as_ref() else {
            return;
        };
        let key = format!("{}/{}", open.name, filter.actions.join(","));
        if !self.seen_filters.insert(key) {
            return;
        }
        if self.manifest.intent_filters.len() < MAX_LISTED {
            let kind = match open.kind.as_str() {
                "activity-alias" => "activity",
                k => k,
            };
            self.manifest.intent_filters.push(IntentFilterDef {
                component: open.name.clone(),
                component_kind: kind.to_owned(),
                actions: filter.actions,
                categories: filter.categories,
                schemes: filter.schemes,
                hosts: filter.hosts,
            });
        } else {
            self.manifest.intent_filters_omitted += 1;
        }
    }

    /// Records the component being read, if other apps can reach it.
    fn close_component(&mut self) {
        self.close_intent_filter();
        let Some(open) = self.open.take() else {
            return;
        };
        if open.enabled == Some(false) || self.application_enabled == Some(false) {
            return;
        }
        let explicitly_exported_provider = open.kind == "provider" && open.exported == Some(true);
        let exposure = match (open.exported, open.filtered) {
            (Some(true), _) => Exposure::Exported,
            (None, true) if open.kind != "provider" => Exposure::ImplicitByIntentFilter,
            _ => return,
        };
        let manifest = &mut self.manifest;
        if explicitly_exported_provider {
            for authority in &open.authorities {
                if manifest.explicitly_exported_provider_authorities.len() < MAX_LISTED
                    && !manifest
                        .explicitly_exported_provider_authorities
                        .iter()
                        .any(|known| known == authority)
                {
                    manifest
                        .explicitly_exported_provider_authorities
                        .push(authority.clone());
                }
            }
        }
        if manifest.reachable_components.len() < MAX_LISTED {
            manifest.reachable_components.push(Component {
                kind: open.kind,
                name: open.name,
                exposure,
            });
        } else {
            manifest.reachable_components_omitted += 1;
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct XmlNode {
    pub name: String,
    pub parent: Option<usize>,
    pub attributes: Vec<(String, String)>,
    pub text: String,
}

impl XmlNode {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Bounded generic binary-XML node reader for manifest-referenced resource XML.
/// Unlike filename-based scanning, this is only called on the exact resolved ZIP member.
pub(super) fn xml_nodes(data: &[u8]) -> Result<Vec<XmlNode>, String> {
    let (kind, header, size) = chunk(data, 0, data.len())?;
    if kind != RES_XML_TYPE {
        return Err("not Android binary XML".to_owned());
    }
    let mut document = Document {
        strings: Vec::new(),
        resource_ids: Vec::new(),
    };
    let mut nodes: Vec<XmlNode> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut at = header;
    while at + 8 <= size {
        let (kind, header, length) = chunk(data, at, size)?;
        match kind {
            RES_STRING_POOL_TYPE if document.strings.is_empty() => {
                document.strings = string_pool(data, at, header, length)?;
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                document.resource_ids = data[at + header..at + length]
                    .chunks_exact(4)
                    .map(|id| u32::from_le_bytes([id[0], id[1], id[2], id[3]]))
                    .collect();
            }
            RES_XML_START_ELEMENT_TYPE => {
                if nodes.len() >= 4096 || stack.len() >= MAX_DEPTH {
                    return Err("resource XML exceeds node/depth budget".to_owned());
                }
                let name_index =
                    le32(data, at + header + 4).ok_or("truncated resource XML element")?;
                let name = document.string(name_index).unwrap_or_default().to_owned();
                let attrs = document
                    .attributes(data, at, header)
                    .ok_or("truncated resource XML attributes")?;
                if attrs.len() > 256 {
                    return Err("resource XML element exceeds attribute budget".to_owned());
                }
                let index = nodes.len();
                nodes.push(XmlNode {
                    name,
                    parent: stack.last().copied(),
                    attributes: attrs.into_iter().map(|a| (a.name, a.value)).collect(),
                    text: String::new(),
                });
                stack.push(index);
            }
            RES_XML_CDATA_TYPE => {
                let index = *stack.last().ok_or("resource XML text outside root")?;
                let string_index = le32(data, at + header).ok_or("truncated resource XML text")?;
                let value = document.string(string_index).unwrap_or_default();
                if nodes[index].text.len().saturating_add(value.len()) > 2048 {
                    return Err("resource XML text exceeds budget".to_owned());
                }
                nodes[index].text.push_str(value);
            }
            RES_XML_END_ELEMENT_TYPE => {
                let name_index =
                    le32(data, at + header + 4).ok_or("truncated resource XML closing element")?;
                let name = document.string(name_index).unwrap_or_default();
                let index = stack
                    .pop()
                    .ok_or("resource XML closing element without start")?;
                if nodes[index].name != name {
                    return Err("mismatched resource XML closing element".to_owned());
                }
            }
            _ => {}
        }
        at += length;
    }
    if at != size || !stack.is_empty() || nodes.is_empty() {
        return Err("incomplete resource XML".to_owned());
    }
    Ok(nodes)
}

/// Decode a compiled `AndroidManifest.xml`.
///
/// # Errors
/// A file that is not binary XML, or whose chunks do not fit inside it, is refused with what was
/// wrong; a plain-text manifest (a source tree, not a built APK) is refused too.
pub fn manifest(data: &[u8]) -> Result<Manifest, String> {
    let (kind, header, size) = chunk(data, 0, data.len()).map_err(|_| "not Android binary XML")?;
    if kind != RES_XML_TYPE {
        return Err("not Android binary XML".to_owned());
    }
    let mut document = Document {
        strings: Vec::new(),
        resource_ids: Vec::new(),
    };
    let mut reader = Reader::default();
    let mut stack: Vec<String> = Vec::new();
    let mut at = header;
    while at + 8 <= size {
        let (kind, header, length) = chunk(data, at, size)?;
        match kind {
            RES_STRING_POOL_TYPE if document.strings.is_empty() => {
                document.strings = string_pool(data, at, header, length)?;
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                document.resource_ids = data[at + header..at + length]
                    .chunks_exact(4)
                    .map(|id| u32::from_le_bytes([id[0], id[1], id[2], id[3]]))
                    .collect();
            }
            RES_XML_START_ELEMENT_TYPE => {
                let name = le32(data, at + header + 4).ok_or("truncated element")?;
                let element = document.string(name).unwrap_or_default().to_owned();
                let attributes = document
                    .attributes(data, at, header)
                    .ok_or("truncated element attributes")?;
                if stack.len() >= MAX_DEPTH {
                    return Err(format!("elements nest deeper than {MAX_DEPTH}"));
                }
                reader.start(&element, stack.last().map(String::as_str), &attributes);
                stack.push(element);
            }
            RES_XML_END_ELEMENT_TYPE => {
                if let Some(element) = stack.pop() {
                    if element == "intent-filter" {
                        reader.close_intent_filter();
                    } else if COMPONENTS.contains(&element.as_str())
                        && stack.last().map(String::as_str) == Some("application")
                    {
                        reader.close_component();
                    }
                }
            }
            _ => {}
        }
        at += length;
    }
    reader.close_component();
    if reader.manifest.package.is_none() && stack.is_empty() && reader.manifest.components == 0 {
        // Nothing a manifest declares was found: report it rather than an empty manifest.
        if document.strings.is_empty() {
            return Err("binary XML has no string pool".to_owned());
        }
    }
    let mut manifest = reader.manifest;
    manifest.permissions.sort();
    manifest.deep_link_hosts.sort();
    manifest.deep_link_schemes.sort();
    manifest.provider_authorities.sort();
    manifest.explicitly_exported_provider_authorities.sort();
    Ok(manifest)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A compiled-manifest builder for tests: a UTF-16 string pool, a resource map naming the
    /// first `ids.len()` strings, and start/end elements with typed attributes.
    pub(crate) struct Axml {
        strings: Vec<String>,
        ids: Vec<u32>,
        body: Vec<u8>,
    }

    pub(crate) enum Val<'a> {
        Str(&'a str),
        Int(i32),
        Bool(bool),
        /// A resource reference carrying a raw resource id (`android:label="@0x…"`).
        Ref(u32),
    }

    impl Axml {
        /// `attrs` are the attribute names, each mapped to its framework ID when it has one.
        pub(crate) fn new(attrs: &[&str]) -> Self {
            let ids = attrs
                .iter()
                .map(|name| {
                    ATTRIBUTE_IDS
                        .iter()
                        .find(|(_, known)| known == name)
                        .map_or(0, |(id, _)| *id)
                })
                .collect();
            Self {
                strings: attrs.iter().map(|name| (*name).to_owned()).collect(),
                ids,
                body: Vec::new(),
            }
        }

        fn intern(&mut self, text: &str) -> u32 {
            let found = self.strings.iter().position(|known| known == text);
            let index = found.unwrap_or_else(|| {
                self.strings.push(text.to_owned());
                self.strings.len() - 1
            });
            u32::try_from(index).unwrap()
        }

        pub(crate) fn start(&mut self, element: &str, attrs: &[(&str, Val<'_>)]) -> &mut Self {
            let name = self.intern(element);
            let mut encoded = Vec::new();
            for (attr, val) in attrs {
                let attr = self.intern(attr);
                let (raw, kind, data) = match val {
                    Val::Str(text) => {
                        let index = self.intern(text);
                        (index, TYPE_STRING, index)
                    }
                    Val::Int(number) => (
                        NO_INDEX,
                        TYPE_INT_DEC,
                        u32::from_le_bytes(number.to_le_bytes()),
                    ),
                    Val::Bool(on) => (NO_INDEX, TYPE_INT_BOOLEAN, if *on { u32::MAX } else { 0 }),
                    Val::Ref(id) => (NO_INDEX, TYPE_REFERENCE, *id),
                };
                encoded.extend_from_slice(&NO_INDEX.to_le_bytes());
                encoded.extend_from_slice(&attr.to_le_bytes());
                encoded.extend_from_slice(&raw.to_le_bytes());
                encoded.extend_from_slice(&8_u16.to_le_bytes());
                encoded.push(0);
                encoded.push(kind);
                encoded.extend_from_slice(&data.to_le_bytes());
            }
            let size = 16 + 20 + encoded.len();
            self.body
                .extend_from_slice(&RES_XML_START_ELEMENT_TYPE.to_le_bytes());
            self.body.extend_from_slice(&16_u16.to_le_bytes());
            self.body
                .extend_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
            self.body.extend_from_slice(&[0; 8]);
            self.body.extend_from_slice(&NO_INDEX.to_le_bytes());
            self.body.extend_from_slice(&name.to_le_bytes());
            self.body.extend_from_slice(&20_u16.to_le_bytes());
            self.body.extend_from_slice(&20_u16.to_le_bytes());
            self.body
                .extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_le_bytes());
            self.body.extend_from_slice(&[0; 6]);
            self.body.extend_from_slice(&encoded);
            self
        }

        pub(crate) fn text(&mut self, value: &str) -> &mut Self {
            let index = self.intern(value);
            self.body
                .extend_from_slice(&RES_XML_CDATA_TYPE.to_le_bytes());
            self.body.extend_from_slice(&16_u16.to_le_bytes());
            self.body.extend_from_slice(&28_u32.to_le_bytes());
            self.body.extend_from_slice(&[0; 8]);
            self.body.extend_from_slice(&index.to_le_bytes());
            self.body.extend_from_slice(&8_u16.to_le_bytes());
            self.body.push(0);
            self.body.push(TYPE_STRING);
            self.body.extend_from_slice(&index.to_le_bytes());
            self
        }

        pub(crate) fn end(&mut self, element: &str) -> &mut Self {
            let name = self.intern(element);
            self.body
                .extend_from_slice(&RES_XML_END_ELEMENT_TYPE.to_le_bytes());
            self.body.extend_from_slice(&16_u16.to_le_bytes());
            self.body.extend_from_slice(&24_u32.to_le_bytes());
            self.body.extend_from_slice(&[0; 8]);
            self.body.extend_from_slice(&NO_INDEX.to_le_bytes());
            self.body.extend_from_slice(&name.to_le_bytes());
            self
        }

        /// Blanks every attribute-name string, as an obfuscator does, keeping the resource map.
        pub(crate) fn blank_attribute_names(&mut self) -> &mut Self {
            for name in self.strings.iter_mut().take(self.ids.len()) {
                name.clear();
            }
            self
        }

        pub(crate) fn build(&self) -> Vec<u8> {
            let mut offsets = Vec::new();
            let mut text = Vec::new();
            for string in &self.strings {
                offsets.extend_from_slice(&u32::try_from(text.len()).unwrap().to_le_bytes());
                let units: Vec<u16> = string.encode_utf16().collect();
                text.extend_from_slice(&u16::try_from(units.len()).unwrap().to_le_bytes());
                for unit in units {
                    text.extend_from_slice(&unit.to_le_bytes());
                }
                text.extend_from_slice(&[0, 0]);
            }
            while text.len() % 4 != 0 {
                text.push(0);
            }
            let strings_start = 28 + offsets.len();
            let pool_size = strings_start + text.len();
            let mut pool = Vec::new();
            pool.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
            pool.extend_from_slice(&28_u16.to_le_bytes());
            pool.extend_from_slice(&u32::try_from(pool_size).unwrap().to_le_bytes());
            pool.extend_from_slice(&u32::try_from(self.strings.len()).unwrap().to_le_bytes());
            pool.extend_from_slice(&0_u32.to_le_bytes());
            pool.extend_from_slice(&0_u32.to_le_bytes());
            pool.extend_from_slice(&u32::try_from(strings_start).unwrap().to_le_bytes());
            pool.extend_from_slice(&0_u32.to_le_bytes());
            pool.extend_from_slice(&offsets);
            pool.extend_from_slice(&text);
            let mut map = Vec::new();
            map.extend_from_slice(&RES_XML_RESOURCE_MAP_TYPE.to_le_bytes());
            map.extend_from_slice(&8_u16.to_le_bytes());
            map.extend_from_slice(&u32::try_from(8 + self.ids.len() * 4).unwrap().to_le_bytes());
            for id in &self.ids {
                map.extend_from_slice(&id.to_le_bytes());
            }
            let total = 8 + pool.len() + map.len() + self.body.len();
            let mut out = Vec::new();
            out.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
            out.extend_from_slice(&8_u16.to_le_bytes());
            out.extend_from_slice(&u32::try_from(total).unwrap().to_le_bytes());
            out.extend_from_slice(&pool);
            out.extend_from_slice(&map);
            out.extend_from_slice(&self.body);
            out
        }
    }

    /// A manifest with the facts an investigator pivots on, as aapt2 would compile it.
    pub(crate) fn sample_manifest() -> Axml {
        let mut axml = Axml::new(&[
            "name",
            "exported",
            "scheme",
            "host",
            "versionCode",
            "versionName",
            "minSdkVersion",
            "targetSdkVersion",
            "debuggable",
            "allowBackup",
            "usesCleartextTraffic",
            "autoVerify",
            "authorities",
        ]);
        axml.start(
            "manifest",
            &[
                ("versionCode", Val::Int(42)),
                ("versionName", Val::Str("4.2.0")),
                ("package", Val::Str("com.example.field")),
            ],
        )
        .start(
            "uses-sdk",
            &[
                ("minSdkVersion", Val::Int(24)),
                ("targetSdkVersion", Val::Int(34)),
            ],
        )
        .end("uses-sdk")
        .start(
            "uses-permission",
            &[("name", Val::Str("android.permission.READ_SMS"))],
        )
        .end("uses-permission")
        .start(
            "uses-permission",
            &[("name", Val::Str("android.permission.INTERNET"))],
        )
        .end("uses-permission")
        .start(
            "application",
            &[
                ("debuggable", Val::Bool(true)),
                ("allowBackup", Val::Bool(false)),
                ("usesCleartextTraffic", Val::Bool(true)),
            ],
        )
        .start(
            "activity",
            &[("name", Val::Str(".Main")), ("exported", Val::Bool(true))],
        )
        .start("intent-filter", &[("autoVerify", Val::Bool(true))])
        .start(
            "data",
            &[
                ("scheme", Val::Str("HTTPS")),
                ("host", Val::Str("Links.Example.com")),
            ],
        )
        .end("data")
        .end("intent-filter")
        .end("activity")
        .start("receiver", &[("name", Val::Str(".Boot"))])
        .start("intent-filter", &[])
        .end("intent-filter")
        .end("receiver")
        .start(
            "service",
            &[
                ("name", Val::Str(".Private")),
                ("exported", Val::Bool(false)),
            ],
        )
        .end("service")
        .start(
            "provider",
            &[
                ("name", Val::Str(".Files")),
                (
                    "authorities",
                    Val::Str("com.example.files;com.example.share"),
                ),
            ],
        )
        .end("provider")
        .end("application")
        .end("manifest");
        axml
    }

    #[test]
    fn reads_what_a_compiled_manifest_declares() {
        let manifest = manifest(&sample_manifest().build()).expect("manifest");
        assert_eq!(manifest.package.as_deref(), Some("com.example.field"));
        assert_eq!(manifest.version_code.as_deref(), Some("42"));
        assert_eq!(manifest.version_name.as_deref(), Some("4.2.0"));
        assert_eq!(manifest.min_sdk.as_deref(), Some("24"));
        assert_eq!(manifest.target_sdk.as_deref(), Some("34"));
        assert_eq!(
            manifest.permissions,
            ["android.permission.INTERNET", "android.permission.READ_SMS"]
        );
        assert_eq!(manifest.debuggable, Some(true));
        assert_eq!(manifest.allow_backup, Some(false));
        assert_eq!(manifest.uses_cleartext_traffic, Some(true));
        assert_eq!(manifest.components, 4);
        assert_eq!(
            manifest.reachable_components,
            [
                Component {
                    kind: "activity".into(),
                    name: ".Main".into(),
                    exposure: Exposure::Exported,
                },
                Component {
                    kind: "receiver".into(),
                    name: ".Boot".into(),
                    exposure: Exposure::ImplicitByIntentFilter,
                },
            ],
            "an explicitly unexported service and a provider with no filter are not reachable"
        );
        assert_eq!(manifest.deep_link_schemes, ["https"]);
        assert_eq!(manifest.deep_link_hosts, ["links.example.com"]);
        assert!(manifest.app_links_auto_verify);
        assert_eq!(
            manifest.provider_authorities,
            ["com.example.files", "com.example.share"]
        );
    }

    #[test]
    fn blanked_attribute_names_resolve_by_resource_id_as_android_does() {
        let mut axml = sample_manifest();
        axml.blank_attribute_names();
        let manifest = manifest(&axml.build()).expect("manifest");
        assert_eq!(manifest.version_code.as_deref(), Some("42"));
        assert_eq!(manifest.target_sdk.as_deref(), Some("34"));
        assert_eq!(manifest.debuggable, Some(true));
        assert_eq!(manifest.deep_link_hosts, ["links.example.com"]);
        assert_eq!(manifest.reachable_components.len(), 2);
        // `package` has no framework ID, so it is still read by its (unblanked) name.
        assert_eq!(manifest.package.as_deref(), Some("com.example.field"));
    }

    #[test]
    fn the_application_label_is_captured_as_a_reference_or_an_inline_string() {
        let referenced = Axml::new(&["package"])
            .start("manifest", &[("package", Val::Str("com.example.field"))])
            .start("application", &[("label", Val::Ref(0x7f0e_0001))])
            .end("application")
            .end("manifest")
            .build();
        let decoded = manifest(&referenced).expect("manifest");
        assert_eq!(decoded.label_resource_id, Some(0x7f0e_0001));
        assert_eq!(decoded.label, None, "a reference is not an inline label");

        let inline = Axml::new(&["package"])
            .start("manifest", &[("package", Val::Str("com.example.field"))])
            .start("application", &[("label", Val::Str("Field Tracker"))])
            .end("application")
            .end("manifest")
            .build();
        let decoded = manifest(&inline).expect("manifest");
        assert_eq!(decoded.label.as_deref(), Some("Field Tracker"));
        assert_eq!(decoded.label_resource_id, None);
    }

    #[test]
    fn refuses_text_and_truncated_binary_xml() {
        assert!(manifest(b"<?xml version=\"1.0\"?><manifest/>").is_err());
        let bytes = sample_manifest().build();
        for cut in [4, 12, bytes.len() / 2, bytes.len() - 3] {
            assert!(manifest(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let mut lying = bytes.clone();
        lying[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(manifest(&lying).is_err());
    }
    #[test]
    fn exported_provider_authorities_remain_bound_to_their_own_component() {
        let mut xml = Axml::new(&["name", "exported", "authorities", "enabled"]);
        xml.start("manifest", &[("package", Val::Str("com.example.test"))])
            .start("application", &[])
            .start(
                "provider",
                &[
                    ("name", Val::Str(".Public")),
                    ("exported", Val::Bool(true)),
                    ("authorities", Val::Str("com.example.public")),
                ],
            )
            .end("provider")
            .start(
                "provider",
                &[
                    ("name", Val::Str(".PrivateContacts")),
                    ("exported", Val::Bool(false)),
                    ("authorities", Val::Str("com.example.contacts")),
                ],
            )
            .end("provider")
            .start(
                "provider",
                &[
                    ("name", Val::Str(".DisabledSms")),
                    ("exported", Val::Bool(true)),
                    ("enabled", Val::Bool(false)),
                    ("authorities", Val::Str("com.example.sms")),
                ],
            )
            .end("provider")
            .end("application")
            .end("manifest");
        let parsed = manifest(&xml.build()).expect("valid binary manifest");
        assert_eq!(
            parsed.provider_authorities,
            [
                "com.example.contacts",
                "com.example.public",
                "com.example.sms"
            ]
        );
        assert_eq!(
            parsed.explicitly_exported_provider_authorities,
            ["com.example.public"]
        );
        assert!(
            !crate::apk_intel::risk::flags(&parsed)
                .iter()
                .any(|flag| flag.id == "reachable_content_provider"),
            "a private sensitive authority must not be attributed to another exported provider"
        );
    }

    #[test]
    fn disabled_application_does_not_expose_its_provider() {
        let mut xml = Axml::new(&["name", "exported", "authorities", "enabled"]);
        xml.start("manifest", &[("package", Val::Str("com.example.test"))])
            .start("application", &[("enabled", Val::Bool(false))])
            .start(
                "provider",
                &[
                    ("name", Val::Str(".Contacts")),
                    ("exported", Val::Bool(true)),
                    ("authorities", Val::Str("com.example.contacts")),
                ],
            )
            .end("provider")
            .end("application")
            .end("manifest");
        let parsed = manifest(&xml.build()).expect("valid binary manifest");
        assert!(parsed.explicitly_exported_provider_authorities.is_empty());
        assert!(parsed.reachable_components.is_empty());
    }

    #[test]
    fn explicitly_exported_sensitive_provider_produces_cautious_risk_flag() {
        let mut xml = Axml::new(&["name", "exported", "authorities"]);
        xml.start("manifest", &[("package", Val::Str("com.example.test"))])
            .start("application", &[])
            .start(
                "provider",
                &[
                    ("name", Val::Str(".Contacts")),
                    ("exported", Val::Bool(true)),
                    ("authorities", Val::Str("com.example.contacts")),
                ],
            )
            .end("provider")
            .end("application")
            .end("manifest");
        let parsed = manifest(&xml.build()).expect("valid binary manifest");
        assert_eq!(
            parsed.explicitly_exported_provider_authorities,
            ["com.example.contacts"]
        );
        let findings = crate::apk_intel::risk::flags(&parsed);
        assert!(findings.iter().any(|flag| {
            flag.id == "reachable_content_provider"
                && flag.detail.contains("manifest names do not prove")
        }));
    }
}
