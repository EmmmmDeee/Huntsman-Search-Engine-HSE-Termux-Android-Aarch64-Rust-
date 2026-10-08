//! One operator repository. This is not a second engine.

pub const REPOSITORY: &str =
    "EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-";
pub const BINARY: &str = "huntsman-recon";
pub const TARGET: &str = "aarch64-linux-android";
pub const ROOT: bool = false;

#[must_use]
pub fn is_operator_binary(name: &str) -> bool {
    name == BINARY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_installed_binary_is_current() {
        assert!(is_operator_binary("huntsman-recon"));
        assert!(!is_operator_binary("hse"));
        assert!(!is_operator_binary("huntsman-rcvf"));
        assert!(!ROOT);
        assert_eq!(TARGET, "aarch64-linux-android");
    }
}
