//! Offline comparison of Android v2/v3 chunked SHA-256 content-digest declarations.
//! Matching bytes are NOT proof of a valid signature: the signed-data claim is untrusted.

use serde::Serialize;

use super::signer;
use crate::sha256::{Sha256, hex32};

const CHUNK_BYTES: usize = 1024 * 1024;
const MAX_CHECKS: usize = 64;
const MAX_ERRORS: usize = 8;

#[derive(Debug, Clone, Serialize)]
pub struct ContentDigestCheck {
    pub scheme: String,
    pub signer_index: usize,
    pub signature_algorithm_id: u32,
    pub declared_sha256: String,
    pub computed_sha256: String,
    pub matches: bool,
    /// Matching a declared digest does not verify the signature over that declaration.
    pub signature_authenticated: bool,
}

/// Compute AOSP's SHA-256 content digest of sections 1, 3 and 4, omitting the
/// signing block and rewriting the EOCD central-directory offset to block start.
fn chunked_sha256(
    apk: &[u8],
    signing_start: usize,
    directory_start: usize,
    eocd_at: usize,
) -> Option<[u8; 32]> {
    if signing_start > directory_start || directory_start > eocd_at {
        return None;
    }
    let offset = u32::try_from(signing_start).ok()?;
    let end = apk.get(eocd_at..)?;
    if end.get(..4)? != b"PK\x05\x06" || end.len() < 22 {
        return None;
    }
    let mut corrected_end = end.to_vec();
    corrected_end[16..20].copy_from_slice(&offset.to_le_bytes());
    let sections = [
        apk.get(..signing_start)?,
        apk.get(directory_start..eocd_at)?,
        corrected_end.as_slice(),
    ];
    let chunks = sections
        .iter()
        .map(|part| part.len().div_ceil(CHUNK_BYTES))
        .sum::<usize>();
    let count = u32::try_from(chunks).ok()?;
    let mut root = Sha256::new();
    root.update(&[0x5a]);
    root.update(&count.to_le_bytes());
    for section in sections {
        for part in section.chunks(CHUNK_BYTES) {
            let mut chunk = Sha256::new();
            chunk.update(&[0xa5]);
            chunk.update(&u32::try_from(part.len()).ok()?.to_le_bytes());
            chunk.update(part);
            root.update(&chunk.finalize());
        }
    }
    Some(root.finalize())
}

pub(super) fn compare(
    apk: &[u8],
    signing_start: usize,
    directory_start: usize,
    eocd_at: usize,
    signing_values: &[(&str, &[u8])],
) -> (Vec<ContentDigestCheck>, Vec<String>) {
    let mut checks = Vec::new();
    let mut errors = Vec::new();
    let mut computed = None;
    for (scheme, value) in signing_values {
        let Some(claims) = signer::sha256_digests(value, scheme) else {
            if errors.len() < MAX_ERRORS {
                errors.push(format!("{scheme}: malformed signer digest declarations"));
            }
            continue;
        };
        for (signer_index, algorithm_id, declared) in claims {
            if checks.len() >= MAX_CHECKS {
                if errors.len() < MAX_ERRORS {
                    errors.push("APK SHA-256 digest observations exceed the report limit".into());
                }
                return (checks, errors);
            }
            let actual = if let Some(actual) = computed {
                actual
            } else {
                let Some(actual) = chunked_sha256(apk, signing_start, directory_start, eocd_at)
                else {
                    if errors.len() < MAX_ERRORS {
                        errors.push("invalid APK content-digest boundaries".into());
                    }
                    return (checks, errors);
                };
                computed = Some(actual);
                actual
            };
            checks.push(ContentDigestCheck {
                scheme: (*scheme).to_owned(),
                signer_index,
                signature_algorithm_id: algorithm_id,
                declared_sha256: hex32(&declared),
                computed_sha256: hex32(&actual),
                matches: declared == actual,
                signature_authenticated: false,
            });
        }
    }
    (checks, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Vec<u8> {
        let mut apk = b"ABCDSIGBLOCKCENTRAL".to_vec();
        let mut end = [0_u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[16..20].copy_from_slice(&12_u32.to_le_bytes());
        apk.extend_from_slice(&end);
        apk
    }

    #[test]
    fn aosp_chunked_digest_matches_independent_sha256_vector() {
        // Independently generated with Python hashlib, following AOSP's 0xa5/0x5a
        // framing and EOCD rewrite. Signing block bytes are excluded.
        let apk = example();
        assert_eq!(
            hex32(&chunked_sha256(&apk, 4, 12, 19).unwrap()),
            "e687e24a92e32601fdd6618eea55b5ee5fa3063ae71376e45bfb2c671062777e"
        );
        assert!(chunked_sha256(&apk, 20, 12, 19).is_none());
    }

    #[test]
    fn matching_untrusted_claim_and_tampered_payload_are_distinguished() {
        let apk = example();
        let digest = chunked_sha256(&apk, 4, 12, 19).unwrap();
        let cert = signer::tests::certificate_der("Digest Claim");
        let value = signer::tests::signing_value_with_sha256_digest(&cert, &digest);
        let (checks, errors) = compare(&apk, 4, 12, 19, &[("v2", &value)]);
        assert!(errors.is_empty());
        assert_eq!(checks.len(), 1);
        assert!(checks[0].matches);
        assert!(!checks[0].signature_authenticated);
        let mut tampered = apk;
        tampered[0] ^= 1;
        let (checks, errors) = compare(&tampered, 4, 12, 19, &[("v2", &value)]);
        assert!(errors.is_empty());
        assert!(!checks[0].matches);
    }
}
