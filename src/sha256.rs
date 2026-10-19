//! Compact SHA-256. The NIST empty, "abc", two-block, and padding-boundary vectors
//! are the acceptance tests.
//! In-tree so the ledger hash does not depend on a second crate.

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Incremental SHA-256 with a constant-size, 64-byte input buffer.
///
/// The bit length uses the SHA-256 mandated 64-bit modulo arithmetic. Caller
/// data is consumed in place rather than copied into a whole-message buffer.
/// Finalization consumes the state; it cannot accidentally be finalized twice.
pub struct Sha256 {
    state: [u32; 8],
    total_bytes: u64,
    buffer: [u8; 64],
    buffered: usize,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Start a fresh SHA-256 calculation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            total_bytes: 0,
            buffer: [0_u8; 64],
            buffered: 0,
        }
    }

    /// Append another chunk; it need not align to a SHA-256 block boundary.
    pub fn update(&mut self, mut input: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(input.len() as u64);
        if self.buffered > 0 {
            let take = input.len().min(64 - self.buffered);
            self.buffer[self.buffered..self.buffered + take]
                .copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered == 64 {
                compress(&mut self.state, &self.buffer);
                self.buffered = 0;
            }
        }

        let mut chunks = input.chunks_exact(64);
        for block in &mut chunks {
            compress(&mut self.state, block);
        }
        let remainder = chunks.remainder();
        self.buffer[..remainder.len()].copy_from_slice(remainder);
        self.buffered = remainder.len();
    }

    /// Finalize with SHA-256 padding and return the 32-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let mut final_blocks = [0_u8; 128];
        final_blocks[..self.buffered].copy_from_slice(&self.buffer[..self.buffered]);
        final_blocks[self.buffered] = 0x80;
        let padded_len = if self.buffered < 56 { 64 } else { 128 };
        let bit_len = self.total_bytes.wrapping_mul(8);
        final_blocks[padded_len - 8..padded_len].copy_from_slice(&bit_len.to_be_bytes());
        for block in final_blocks[..padded_len].chunks_exact(64) {
            compress(&mut self.state, block);
        }

        let mut out = [0_u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// SHA-256 of a single byte slice, compatible with the incremental hasher.
/// Hashing does not allocate input-sized copies or padding.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

fn compress(h: &mut [u32; 8], chunk: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            chunk[i * 4],
            chunk[i * 4 + 1],
            chunk[i * 4 + 2],
            chunk[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut a = *h;
    for i in 0..64 {
        let s1 = a[4].rotate_right(6) ^ a[4].rotate_right(11) ^ a[4].rotate_right(25);
        let ch = (a[4] & a[5]) ^ (!a[4] & a[6]);
        let t1 = a[7]
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a[0].rotate_right(2) ^ a[0].rotate_right(13) ^ a[0].rotate_right(22);
        let maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
        let t2 = s0.wrapping_add(maj);
        a[7] = a[6];
        a[6] = a[5];
        a[5] = a[4];
        a[4] = a[3].wrapping_add(t1);
        a[3] = a[2];
        a[2] = a[1];
        a[1] = a[0];
        a[0] = t1.wrapping_add(t2);
    }
    for i in 0..8 {
        h[i] = h[i].wrapping_add(a[i]);
    }
}

#[must_use]
pub fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_empty_and_abc() {
        assert_eq!(
            hex32(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex32(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Multi-block messages and the padding boundary. When the input length leaves no
    /// room for the 0x80 byte plus the 8-byte length in the final 64-byte block
    /// (`len % 64` in `56..=63`), the padding spills into a second block. The empty and
    /// "abc" vectors above are single-block and never exercise that path, so a padding
    /// defect would corrupt the ledger hash chain undetected. Each digest was produced
    /// with `sha256sum` and `openssl dgst -sha256` (agreeing); the two-block strings and
    /// the one-million-'a' value are the documented NIST / FIPS 180 vectors.
    #[test]
    fn nist_multiblock_and_padding_boundary() {
        let a = |n: usize| vec![b'a'; n];
        for (input, want) in [
            // len % 64 == 55: 0x80 and length still fit in one block.
            (
                a(55),
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            // len % 64 == 56: the first length byte no longer fits; padding spills.
            (
                a(56),
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            ),
            (
                a(63),
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            ),
            // Exactly one block of data: all padding lands in a second block.
            (
                a(64),
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                a(1000),
                "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
            ),
            // The classic FIPS 180 one-million-'a' vector.
            (
                a(1_000_000),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ] {
            assert_eq!(hex32(&sha256(&input)), want, "{} bytes of 'a'", input.len());
        }
        // The two canonical NIST two-block vectors (56 and 112 bytes).
        assert_eq!(
            hex32(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex32(&sha256(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }
    #[test]
    fn binary_vectors_across_padding_and_block_boundaries() {
        for (length, expected) in [
            (
                55_usize,
                "4b587256d77fdf91e5d2b485b7bef8e498fac5dc88c724c30267a0d96222f9b7",
            ),
            (
                56,
                "4360272affef439b717f1c6c3b12b806dd844353fa53bbd0ef63c963fe3109db",
            ),
            (
                63,
                "d6166e0436d0b0e9296e171c13bb88fbc2dbcd1da6b9470b452ae06a9495e9a7",
            ),
            (
                64,
                "ca982c0fc8d1c35f64001571c33f1f34c109ad6c6420637d3d7633bd5c3c649a",
            ),
            (
                65,
                "d96cbc7f13f43e80ddedc86753166e0843d2898ffbb662e6c93c412690b49568",
            ),
            (
                119,
                "0618e277fa04810cee36404f1704459e982579ca7da339f7e27ed2bc987f2abd",
            ),
            (
                120,
                "7ae11528fbabe9755b6b55d01dd8e4a50e45182cff7e3d161b1d49c03eadd947",
            ),
            (
                127,
                "da06012c921524baa736ca49c74c26edff631841368f9aa03c866e186b9da089",
            ),
            (
                128,
                "4ea84049cfc1c375698f9df7d58de283151599431d5a7b804195ec62c29ca0e4",
            ),
            (
                129,
                "7c20a32fb7fb904575bca1c6a1f2c30c754f6a82661718f8e68f5137b9f8487d",
            ),
            (
                257,
                "de524d79c4f2ae863da0fafe9a68d9be00c05a2afddf72b7620d3820c48e71f8",
            ),
            (
                4097,
                "7094d261c319e162a1edb93c47322ba1ac6ea44c3e16b05351fbd1749d9bbd27",
            ),
        ] {
            let bytes: Vec<u8> = (0..length)
                .map(|i| u8::try_from((i * 17 + 91) % 256).expect("byte is reduced modulo 256"))
                .collect();
            assert_eq!(hex32(&sha256(&bytes)), expected, "length {length}");
        }
    }

    #[test]
    fn streaming_chunks_match_single_slice_across_padding_boundaries() {
        for length in 0..=1_024 {
            let bytes = (0..length)
                .map(|position| ((position * 31 + 17) % 256) as u8)
                .collect::<Vec<_>>();
            let expected = sha256(&bytes);
            for chunk in [1, 3, 7, 13, 63, 64, 65, 127, 128, 1_024] {
                let mut hasher = Sha256::new();
                hasher.update(b"");
                for part in bytes.chunks(chunk) {
                    hasher.update(part);
                    hasher.update(b"");
                }
                assert_eq!(
                    hasher.finalize(),
                    expected,
                    "length {length}, chunk size {chunk}"
                );
            }
        }
    }

    #[test]
    fn streaming_million_byte_nist_vector_without_whole_message_copy() {
        let mut hasher = Sha256::new();
        for _ in 0..1_000 {
            hasher.update(&[b'a'; 1_000]);
        }
        assert_eq!(
            hex32(&hasher.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_multiple_updates_and_fresh_default_are_compatible() {
        let expected = sha256(b"abc");
        let mut hasher = Sha256::default();
        hasher.update(b"a");
        hasher.update(b"b");
        hasher.update(b"c");
        assert_eq!(hasher.finalize(), expected);
        assert_eq!(Sha256::default().finalize(), sha256(b""));
    }

}
