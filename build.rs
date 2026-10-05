//! Release-safety build marker for HIBP key handling.
//!
//! Production keys are runtime-only. This build script deliberately never
//! reads or embeds `HIBP_API_KEY`; it emits an empty compatibility marker so
//! release CI can prove that the build-time embed channel contains no secret.

use std::io::Write;
use std::path::PathBuf;

fn main() {
    for name in [
        "HIBP_API_KEY",
        "HOME",
        "CI",
        "HSE_RELEASE",
        "HUNTSMAN_HIBP_NO_EMBED",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home).join(".config/hibp/api_key");
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let path = out.join("hibp_embedded_key.txt");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).expect("open empty HIBP build marker");
    file.write_all(b"").expect("write empty HIBP build marker");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .expect("make HIBP build marker private");
    }
}
