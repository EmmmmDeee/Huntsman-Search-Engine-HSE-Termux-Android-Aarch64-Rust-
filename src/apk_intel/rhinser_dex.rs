//! Bounded, offline RHINSER-specific DEX class and method-name inventory.
//!
//! This is a Rust replacement for the method-name enumeration portion of the
//! archived `analyse_apks.py`. It never executes Android code, calls the radio,
//! infers method semantics, or pretends that DEX references are method bodies.
//! It intentionally reuses the parent APK reader's existing ZIP/CRC/deflate
//! checks; call `inspect` only on DEX bytes yielded by that reader.

use std::collections::BTreeSet;
use serde::Serialize;

const MAX_DEX_BYTES: usize = 128 * 1024 * 1024;
const MAX_STRINGS: usize = 2_000_000;
const MAX_TYPES: usize = 100_000;
const MAX_CLASSES: usize = 50_000;
const MAX_METHOD_IDS: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_APP_METHOD_PAIRS: usize = 20_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MethodName {
    pub class_descriptor: String,
    pub name: String,
    /// A DEX method_id is a reference, not a proof that the class defines it.
    pub class_defined_in_dex: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Inventory {
    pub app_classes_defined: Vec<String>,
    pub app_method_name_pairs: Vec<MethodName>,
    pub method_references_without_class_definition: usize,
    pub omitted_app_method_name_pairs: usize,
    pub source_quality: &'static str,
}

fn u16_at(input: &[u8], offset: usize) -> Result<usize, String> {
    let end = offset.checked_add(2).ok_or("DEX offset overflow")?;
    let bytes = input.get(offset..end).ok_or("truncated DEX u16")?;
    Ok(usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
}
fn u32_at(input: &[u8], offset: usize) -> Result<usize, String> {
    let end = offset.checked_add(4).ok_or("DEX offset overflow")?;
    let bytes = input.get(offset..end).ok_or("truncated DEX u32")?;
    Ok(usize::try_from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .map_err(|_| "DEX integer cannot fit host usize")?)
}
fn table(input: &[u8], count_at: usize, offset_at: usize, stride: usize, limit: usize)
    -> Result<(usize, usize), String> {
    let count = u32_at(input, count_at)?;
    if count > limit { return Err("DEX table exceeds analysis limit".to_owned()); }
    let offset = u32_at(input, offset_at)?;
    let end = offset.checked_add(count.checked_mul(stride).ok_or("DEX table length overflow")?)
        .ok_or("DEX table end overflow")?;
    if end > input.len() { return Err("DEX table extends beyond input".to_owned()); }
    Ok((offset, count))
}
fn uleb(input: &[u8], start: usize) -> Result<usize, String> {
    let mut result = 0_usize;
    for i in 0..5 {
        let at = start.checked_add(i).ok_or("DEX uleb offset overflow")?;
        let byte = *input.get(at).ok_or("truncated DEX uleb")?;
        result |= usize::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 { return Ok(at + 1); }
    }
    Err("DEX uleb value too long".to_owned())
}
fn string_at(input: &[u8], start: usize) -> Result<String, String> {
    let at = uleb(input, start)?;
    let available = input.get(at..).ok_or("DEX string offset invalid")?;
    let count = available.iter().take(MAX_NAME_BYTES + 1).position(|byte| *byte == 0)
        .ok_or("DEX string exceeds bounded analysis limit or is unterminated")?;
    // Dalvik MUTF-8 has different NUL / supplementary encodings. Class and method
    // descriptors of interest here use ASCII; reject ambiguous non-ASCII rather than
    // accidentally conflating distinct identifiers.
    let raw = &available[..count];
    if !raw.is_ascii() { return Err("DEX class/method name is not ASCII".to_owned()); }
    String::from_utf8(raw.to_vec()).map_err(|_| "invalid DEX identifier".to_owned())
}
fn is_rhinser_class(name: &str) -> bool {
    // DEX method IDs may reference an array descriptor such as
    // `[Lcom/rhinse/osint/data/catalog/CatalogRegion;`. That owner is
    // not a class definition, but it is an application-package method ref.
    let lower = name.trim_start_matches('[').to_ascii_lowercase();
    lower.starts_with("lcom/rhinse") || lower.starts_with("lcom/emv/")
}

/// Extract only DEX class definitions and distinct (owner, name) method refs
/// associated with RHINSER/EMV packages. No decompilation or execution occurs.
///
/// # Errors
/// Rejects invalid DEX boundaries, non-ASCII app identifiers, ambiguous
/// indices, unsupported DEX endianness and oversized input.
pub fn inspect(input: &[u8]) -> Result<Inventory, String> {
    if input.len() < 0x70 || input.len() > MAX_DEX_BYTES || &input[..4] != b"dex\n"
        || input[7] != 0 || u32_at(input, 40)? != 0x1234_5678 {
        return Err("unsupported or malformed little-endian DEX".to_owned());
    }
    let (str_offset, strings) = table(input, 56, 60, 4, MAX_STRINGS)?;
    let (type_offset, types) = table(input, 64, 68, 4, MAX_TYPES)?;
    let (method_offset, methods) = table(input, 88, 92, 8, MAX_METHOD_IDS)?;
    let (class_offset, classes) = table(input, 96, 100, 32, MAX_CLASSES)?;
    let mut string_ids = Vec::with_capacity(strings);
    for i in 0..strings {
        string_ids.push(u32_at(input, str_offset + i * 4)?);
    }
    let mut type_names = Vec::with_capacity(types);
    for i in 0..types {
        let string_index = u32_at(input, type_offset + i * 4)?;
        let string_offset = *string_ids.get(string_index)
            .ok_or("DEX type points outside string table")?;
        type_names.push(string_at(input, string_offset)?);
    }
    let mut definitions = BTreeSet::new();
    for i in 0..classes {
        let type_index = u32_at(input, class_offset + i * 32)?;
        let name = type_names.get(type_index)
            .ok_or("DEX class definition references missing type")?;
        if is_rhinser_class(name) {
            definitions.insert(name.clone());
        }
    }
    let mut refs = BTreeSet::new();
    for i in 0..methods {
        let start = method_offset + i * 8;
        let owner = u16_at(input, start)?;
        let name_index = u32_at(input, start + 4)?;
        let name = type_names.get(owner).ok_or("DEX method owner missing from types")?;
        if !is_rhinser_class(name) { continue; }
        let string_offset = *string_ids.get(name_index)
            .ok_or("DEX method name missing from strings")?;
        let method_name = string_at(input, string_offset)?;
        refs.insert((name.clone(), method_name));
        if refs.len() > MAX_APP_METHOD_PAIRS {
            return Err("RHINSER app method-name inventory exceeds safety bound".to_owned());
        }
    }
    let unresolved = refs.iter().filter(|(owner, _)| !definitions.contains(owner)).count();
    let app_method_name_pairs = refs.into_iter().map(|(class_descriptor, name)| {
        let class_defined_in_dex = definitions.contains(&class_descriptor);
        MethodName { class_descriptor, name, class_defined_in_dex }
    }).collect();
    Ok(Inventory {
        app_classes_defined: definitions.into_iter().collect(),
        app_method_name_pairs,
        method_references_without_class_definition: unresolved,
        omitted_app_method_name_pairs: 0,
        source_quality: "static_dex_method_names_only_not_behavioral_parity",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn set32(bytes: &mut [u8], offset: usize, v: u32) {
        bytes[offset..offset+4].copy_from_slice(&v.to_le_bytes());
    }
    fn synthetic() -> Vec<u8> {
        let names = ["Lcom/rhinse/Scan;", "Lcom/emv/Nfc;", "Landroid/view/View;", "scan", "run"];
        let mut d = vec![0_u8; 0x70];
        d[..8].copy_from_slice(b"dex\n035\0");
        set32(&mut d, 40, 0x1234_5678);
        let str_off = d.len(); d.resize(str_off+names.len()*4,0);
        for (i, name) in names.iter().enumerate() {
            let at = u32::try_from(d.len()).unwrap();
            set32(&mut d, str_off+i*4, at);
            d.push(u8::try_from(name.len()).unwrap());
            d.extend_from_slice(name.as_bytes()); d.push(0);
        }
        let type_off=d.len();
        for i in 0_u32..3 { d.extend_from_slice(&i.to_le_bytes()); }
        let method_off=d.len();
        for (owner,idx) in [(0_u16,3_u32),(1,4),(2,4)] {
            d.extend_from_slice(&owner.to_le_bytes());
            d.extend_from_slice(&0_u16.to_le_bytes());
            d.extend_from_slice(&idx.to_le_bytes());
        }
        let class_off=d.len();
        d.extend_from_slice(&0_u32.to_le_bytes()); d.extend_from_slice(&[0_u8;28]);
        for (sz,off,val) in [(56,60,names.len()),(64,68,3),(88,92,3),(96,100,1)] {
            set32(&mut d, sz, u32::try_from(val).unwrap());
            set32(&mut d, off, u32::try_from(match sz { 56=>str_off,64=>type_off,88=>method_off,_=>class_off }).unwrap());
        }
        d
    }
    #[test]
    fn differentiates_defined_classes_from_method_references() {
        let result=inspect(&synthetic()).unwrap();
        assert_eq!(result.app_classes_defined.len(), 1);
        assert_eq!(result.app_method_name_pairs.len(), 2);
        assert_eq!(result.method_references_without_class_definition, 1);
        assert!(result.app_method_name_pairs.iter().any(|x|
            x.name=="run" && !x.class_defined_in_dex));
    }
    #[test]
    fn refuses_bad_header_and_out_of_bounds_tables() {
        let mut d=synthetic();
        assert!(inspect(&d).is_ok());
        d[0]=0; assert!(inspect(&d).is_err());
        d[0]=b'd'; set32(&mut d, 92, u32::MAX);
        assert!(inspect(&d).is_err());
    }
    #[test]
    fn array_type_references_are_kept_but_not_defined_classes() {
        assert!(is_rhinser_class("[Lcom/rhinse/osint/data/catalog/CatalogRegion;"));
        assert!(is_rhinser_class("[[Lcom/emv/Nfc;"));
        assert!(!is_rhinser_class("[Ljava/lang/String;"));
    }
    #[test]
    fn empty_tables_are_valid_not_verified_functionality() {
        let mut d=vec![0;0x70];
        d[..8].copy_from_slice(b"dex\n035\0");set32(&mut d,40,0x1234_5678);
        assert_eq!(inspect(&d).unwrap().app_method_name_pairs.len(),0);
    }
}