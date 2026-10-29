//! Offline AOSP v3/v3.1 signing-certificate rotation proofs.
//!
//! A certificate chain is not APK authentication. A verified result requires the signed
//! ancestor-to-descendant links, the final certificate matching the declared SDK signer,
//! and an independently authenticated APK content digest for that same signer.
use std::collections::BTreeSet;

use serde::Serialize;

use super::{ContentDigestCheck, SdkSigner, signer};
use crate::sha256::sha256;

const PROOF_OF_ROTATION_ID: u32 = 0x3ba0_6f8c;
const MAX_LEVELS: usize = 16;
const MAX_PROOF_BYTES: usize = 1024 * 1024;
const MAX_CERT_BYTES: usize = 64 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RotationCertificate {
    pub certificate_sha256: String,
    pub public_key_sha256: String,
    /// AOSP capability flags, preserved without assigning permissions or ownership.
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotationChain {
    pub scheme: String,
    pub signer_index: usize,
    /// "verified" requires both cryptographic lineage and APK signed-data authentication.
    /// `lineage_verified_apk_unverified` is not evidence of APK signing identity.
    pub status: &'static str,
    pub certificates: Vec<RotationCertificate>,
}

fn parse_proof(
    bytes: &[u8],
    expected_last: &str,
) -> Result<Vec<RotationCertificate>, &'static str> {
    if bytes.len() < 4 || bytes.len() > MAX_PROOF_BYTES {
        return Err("malformed");
    }
    if signer::le32(bytes, 0) != Some(1) {
        return Err("unsupported_version");
    }
    let mut at = 4;
    let mut previous_certificate: Option<&[u8]> = None;
    let mut previous_algorithm = 0_u32;
    let mut seen = BTreeSet::new();
    let mut nodes = Vec::new();
    while at < bytes.len() {
        if nodes.len() == MAX_LEVELS {
            return Err("limit_exceeded");
        }
        let (start, end) = signer::prefixed_one(bytes, at, bytes.len()).ok_or("malformed")?;
        let (node_data_start, node_data_end) =
            signer::prefixed_one(bytes, start, end).ok_or("malformed")?;
        let flags_at = node_data_end;
        let flags = u32::try_from(signer::le32(bytes, flags_at).ok_or("malformed")?)
            .map_err(|_| "malformed")?;
        let next_at = flags_at.checked_add(4).ok_or("malformed")?;
        let next_algorithm = u32::try_from(signer::le32(bytes, next_at).ok_or("malformed")?)
            .map_err(|_| "malformed")?;
        let signature_at = next_at.checked_add(4).ok_or("malformed")?;
        let (signature_start, signature_end) =
            signer::prefixed_one(bytes, signature_at, end).ok_or("malformed")?;
        if signature_end != end || signature_end - signature_start > MAX_SIGNATURE_BYTES {
            return Err("malformed");
        }
        let (cert_start, cert_end) =
            signer::prefixed_one(bytes, node_data_start, node_data_end).ok_or("malformed")?;
        if cert_end - cert_start > MAX_CERT_BYTES || cert_end.checked_add(4) != Some(node_data_end)
        {
            return Err("malformed");
        }
        let signed_algorithm = u32::try_from(signer::le32(bytes, cert_end).ok_or("malformed")?)
            .map_err(|_| "malformed")?;
        let cert_bytes = &bytes[cert_start..cert_end];
        let certificate = signer::certificate(cert_bytes, "rotation").ok_or("malformed")?;
        if !seen.insert(sha256(cert_bytes)) {
            return Err("duplicate_certificate");
        }
        if let Some(previous) = previous_certificate {
            if signed_algorithm != previous_algorithm {
                return Err("algorithm_mismatch");
            }
            match signer::verify_rotation_signature(
                previous,
                previous_algorithm,
                &bytes[node_data_start..node_data_end],
                &bytes[signature_start..signature_end],
            ) {
                Some(true) => {}
                Some(false) => return Err("invalid_signature"),
                None => return Err("unsupported_algorithm"),
            }
        } else if signed_algorithm != 0 || signature_start != signature_end {
            return Err("malformed");
        }
        nodes.push(RotationCertificate {
            certificate_sha256: certificate.sha256,
            public_key_sha256: certificate.public_key_sha256,
            flags,
        });
        previous_certificate = Some(cert_bytes);
        previous_algorithm = next_algorithm;
        at = end;
    }
    if nodes.is_empty()
        || nodes
            .last()
            .is_none_or(|last| last.certificate_sha256 != expected_last)
    {
        return Err("signer_mismatch");
    }
    Ok(nodes)
}

fn signer_attribute(
    value: &[u8],
    signer_start: usize,
    signer_end: usize,
) -> Result<Option<&[u8]>, &'static str> {
    let (data_start, data_end) =
        signer::prefixed_one(value, signer_start, signer_end).ok_or("malformed")?;
    let (_, digests_end) = signer::prefixed_one(value, data_start, data_end).ok_or("malformed")?;
    let (_, certs_end) = signer::prefixed_one(value, digests_end, data_end).ok_or("malformed")?;
    let attrs_at = certs_end.checked_add(8).ok_or("malformed")?;
    let (attrs_start, attrs_end) =
        signer::prefixed_one(value, attrs_at, data_end).ok_or("malformed")?;
    if attrs_end != data_end {
        return Err("malformed");
    }
    let mut found = None;
    for (from, to) in signer::prefixed(value, attrs_start, attrs_end).ok_or("malformed")? {
        let id = u32::try_from(signer::le32(value, from).ok_or("malformed")?)
            .map_err(|_| "malformed")?;
        if from.checked_add(4).is_none_or(|payload| payload > to) {
            return Err("malformed");
        }
        if id == PROOF_OF_ROTATION_ID {
            if found.is_some() {
                return Err("duplicate_attribute");
            }
            found = Some(&value[from + 4..to]);
        }
    }
    Ok(found)
}

/// Read only v3/v3.1 proof-of-rotation attributes. An unsupported or corrupt proof
/// cannot produce a verified signer pivot. The signed-data/content-digest check must
/// be for the same scheme and signer index, never another APK signing record.
pub(super) fn inspect(
    value: &[u8],
    scheme: &str,
    sdk_signers: &[SdkSigner],
    digest_checks: &[ContentDigestCheck],
) -> Vec<RotationChain> {
    if !matches!(scheme, "v3" | "v3.1") {
        return Vec::new();
    }
    if value.len() > MAX_PROOF_BYTES * 2 {
        return Vec::new();
    }
    let Some(outer) = signer::prefixed(value, 0, value.len()) else {
        return Vec::new();
    };
    let [(start, end)] = outer.as_slice() else {
        return Vec::new();
    };
    let Some(signers) = signer::prefixed(value, *start, *end) else {
        return Vec::new();
    };
    if signers.len() > MAX_LEVELS {
        return Vec::new();
    }
    let mut results = Vec::new();
    for (index, (signer_start, signer_end)) in signers.into_iter().enumerate() {
        let Some(claim) = sdk_signers
            .iter()
            .find(|claim| claim.scheme == scheme && claim.signer_index == index)
        else {
            continue;
        };
        let proof = signer_attribute(value, signer_start, signer_end);
        let (status, certificates) = match proof {
            Ok(None) => continue,
            Err(reason) => (reason, Vec::new()),
            Ok(Some(payload)) => match parse_proof(payload, &claim.certificate_sha256) {
                Err(reason) => (reason, Vec::new()),
                Ok(certificates) if certificates.len() < 2 => ("no_rotation", certificates),
                Ok(certificates) => {
                    let authenticated = digest_checks.iter().any(|check| {
                        check.scheme == scheme
                            && check.signer_index == index
                            && check.signature_authenticated
                    });
                    (
                        if authenticated {
                            "verified"
                        } else {
                            "lineage_verified_apk_unverified"
                        },
                        certificates,
                    )
                }
            },
        };
        results.push(RotationChain {
            scheme: scheme.to_owned(),
            signer_index: index,
            status,
            certificates,
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair as _;

    fn prefix(data: &[u8]) -> Vec<u8> {
        let mut result = u32::try_from(data.len()).unwrap().to_le_bytes().to_vec();
        result.extend_from_slice(data);
        result
    }

    fn level(cert: &[u8], signed_alg: u32, next_alg: u32, signature: &[u8]) -> Vec<u8> {
        let mut signed = prefix(cert);
        signed.extend_from_slice(&signed_alg.to_le_bytes());
        let mut node = prefix(&signed);
        node.extend_from_slice(&0_u32.to_le_bytes());
        node.extend_from_slice(&next_alg.to_le_bytes());
        node.extend_from_slice(&prefix(signature));
        prefix(&node)
    }

    fn proof(first: &[u8], second: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut out = 1_u32.to_le_bytes().to_vec();
        out.extend(level(first, 0, 0x0201, &[]));
        out.extend(level(second, 0x0201, 0, signature));
        out
    }

    fn keys() -> (ring::signature::EcdsaKeyPair, ring::signature::EcdsaKeyPair) {
        let rng = ring::rand::SystemRandom::new();
        let make = || {
            let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &rng,
            )
            .unwrap();
            ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                pkcs8.as_ref(),
                &rng,
            )
            .unwrap()
        };
        (make(), make())
    }

    #[test]
    fn authentic_parent_signature_and_current_signer_are_required() {
        let rng = ring::rand::SystemRandom::new();
        let (parent, child) = keys();
        let old = signer::tests::p256_certificate("Old", parent.public_key().as_ref());
        let new = signer::tests::p256_certificate("New", child.public_key().as_ref());
        let mut signed = prefix(&new);
        signed.extend_from_slice(&0x0201_u32.to_le_bytes());
        let signature = parent.sign(&rng, &signed).unwrap();
        let good = proof(&old, &new, signature.as_ref());
        let last = crate::sha256::hex32(&sha256(&new));
        assert_eq!(parse_proof(&good, &last).unwrap().len(), 2);
        assert_eq!(parse_proof(&good, "wrong"), Err("signer_mismatch"));
        let mut corrupted = good.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert_eq!(parse_proof(&corrupted, &last), Err("invalid_signature"));
        assert_eq!(
            parse_proof(&good[..good.len() - 1], &last),
            Err("malformed")
        );
        let mut duplicate = 1_u32.to_le_bytes().to_vec();
        duplicate.extend(level(&old, 0, 0x0201, &[]));
        duplicate.extend(level(&old, 0x0201, 0, signature.as_ref()));
        assert_eq!(parse_proof(&duplicate, &last), Err("duplicate_certificate"));
    }

    fn v3_with_proof(cert: &[u8], proof: &[u8]) -> Vec<u8> {
        let mut record = PROOF_OF_ROTATION_ID.to_le_bytes().to_vec();
        record.extend_from_slice(proof);
        let digests = prefix(&[]);
        let certs = prefix(cert);
        let mut signed = prefix(&digests);
        signed.extend_from_slice(&prefix(&certs));
        signed.extend_from_slice(&28_u32.to_le_bytes());
        signed.extend_from_slice(&35_u32.to_le_bytes());
        signed.extend_from_slice(&prefix(&prefix(&record)));
        let mut signer_record = prefix(&signed);
        signer_record.extend_from_slice(&28_u32.to_le_bytes());
        signer_record.extend_from_slice(&35_u32.to_le_bytes());
        signer_record.extend_from_slice(&prefix(&[]));
        signer_record.extend_from_slice(&prefix(signer::certificate_spki(cert).unwrap()));
        prefix(&prefix(&signer_record))
    }

    #[test]
    fn json_and_evidence_gate_unbound_and_authenticated_proofs() {
        let rng = ring::rand::SystemRandom::new();
        let (parent, child) = keys();
        let old = signer::tests::p256_certificate("Old", parent.public_key().as_ref());
        let new = signer::tests::p256_certificate("New", child.public_key().as_ref());
        let mut signed = prefix(&new);
        signed.extend_from_slice(&0x0201_u32.to_le_bytes());
        let signature = parent.sign(&rng, &signed).unwrap();
        let value = v3_with_proof(&new, &proof(&old, &new, signature.as_ref()));
        let claims = signer::sdk_signers(&value, "v3");
        assert_eq!(claims.len(), 1);
        let unbound = inspect(&value, "v3", &claims, &[]);
        assert_eq!(unbound.len(), 1);
        assert_eq!(unbound[0].status, "lineage_verified_apk_unverified");
        assert_eq!(unbound[0].certificates.len(), 2);
        let check = ContentDigestCheck {
            scheme: "v3".to_owned(),
            signer_index: 0,
            signature_algorithm_id: 0x0201,
            declared_sha256: String::new(),
            computed_sha256: String::new(),
            matches: true,
            signature_authenticated: true,
            signature_verification: "verified",
        };
        let wrong_scheme = ContentDigestCheck {
            scheme: "v2".to_owned(),
            ..check.clone()
        };
        assert_eq!(
            inspect(&value, "v3", &claims, &[wrong_scheme])[0].status,
            "lineage_verified_apk_unverified"
        );
        let bound = inspect(&value, "v3", &claims, &[check]);
        assert_eq!(bound[0].status, "verified");
        let json = serde_json::to_value(&bound).unwrap();
        assert_eq!(json[0]["certificates"].as_array().unwrap().len(), 2);
        assert_eq!(json[0]["status"], "verified");

        let mut analysis = super::super::Analysis {
            rotation_chains: bound,
            ..Default::default()
        };
        let mut attributes = Vec::new();
        super::super::signer_digest_attrs(&analysis, &mut |key, value| {
            attributes.push((key, value));
        });
        assert!(attributes.iter().any(|(key, value)| {
            *key == "apk_rotation_verified_certificates"
                && value.contains(&crate::sha256::hex32(&sha256(&old)))
                && value.contains(&crate::sha256::hex32(&sha256(&new)))
        }));
        analysis.rotation_chains = unbound;
        let mut unverified_attributes = Vec::new();
        super::super::signer_digest_attrs(&analysis, &mut |key, value| {
            unverified_attributes.push((key, value));
        });
        assert!(unverified_attributes.iter().any(|(key, value)| {
            *key == "apk_rotation_verified_certificates" && value.is_empty()
        }));
    }

    #[test]
    fn unsupported_version_and_unbound_lineage_never_verify() {
        let cert = signer::tests::certificate_der("Not Signed");
        let mut one = 1_u32.to_le_bytes().to_vec();
        one.extend(level(&cert, 0, 0, &[]));
        let last = crate::sha256::hex32(&sha256(&cert));
        assert_eq!(parse_proof(&one, &last).unwrap().len(), 1);
        one[..4].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(parse_proof(&one, &last), Err("unsupported_version"));
    }
}
