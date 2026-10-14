//! Release-safety build marker for HIBP key handling.
//!
//! Production keys are runtime-only. This build script deliberately never
//! reads or embeds `HIBP_API_KEY`; it emits an empty compatibility marker so
//! release CI can prove that the build-time embed channel contains no secret.

use std::io::Write;
use std::path::PathBuf;

fn main() {
    // The marker never depends on HOME, CI or a key file, so none of them may make Cargo run
    // this script again. A watched file that does not exist (`~/.config/hibp/api_key` on almost
    // every machine) counts as changed on every build, so watching it recompiled the whole
    // crate and every test binary on each `cargo build` or `cargo test`, even with nothing
    // edited. tests/hibp_build.rs holds this.
    for name in [
        "HIBP_API_KEY",
        "HSE_RELEASE",
        "HUNTSMAN_HIBP_NO_EMBED",
        "HUNTSMAN_BUILD_SHA",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=build.rs");

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
