//! Optional personal-build key embedding. Distributed/release builds never embed.
use std::io::{Read, Write};
use std::path::PathBuf;

fn configured(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return false;
    }
    // Same provisioning-placeholder policy as keys::is_configured_value.
    let lower = value.to_ascii_lowercase();
    if [
        "changeme",
        "change_me",
        "your_key",
        "your-key",
        "todo",
        "null",
        "none",
    ]
    .contains(&lower.as_str())
        || ((lower.starts_with("insert_")
            || lower.starts_with("your_")
            || lower.starts_with("your-"))
            && (lower.ends_with("_here") || lower.ends_with("-here")))
        || (lower.starts_with('<') && lower.ends_with('>'))
        || (lower.starts_with("${") && lower.ends_with('}'))
    {
        return false;
    }
    let mut chars = lower.chars();
    if let Some(first) = chars.next() {
        if matches!(first, 'x' | '*' | '.' | '-' | '_' | '0')
            && value.len() >= 4
            && chars.all(|c| c == first)
        {
            return false;
        }
    }
    true
}

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
    let path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|p| p.join(".config/hibp/api_key"));
    if let Some(path) = &path {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let disabled = ["CI", "HSE_RELEASE", "HUNTSMAN_HIBP_NO_EMBED"]
        .iter()
        .any(|name| std::env::var_os(name).is_some());
    let key = if disabled {
        String::new()
    } else {
        std::env::var("HIBP_API_KEY")
            .ok()
            .filter(|v| configured(v))
            .or_else(|| {
                let path = path?;
                let meta = std::fs::symlink_metadata(&path).ok()?;
                if !meta.is_file() || meta.len() > 4096 {
                    return None;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o077 != 0 {
                        return None;
                    }
                }
                let mut value = String::new();
                std::fs::File::open(path)
                    .ok()?
                    .take(4097)
                    .read_to_string(&mut value)
                    .ok()?;
                (value.len() <= 4096 && configured(&value)).then_some(value)
            })
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(out.join("hibp_embedded_key.txt"))
        .expect("open embedded key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .expect("private embedded key");
    }
    file.write_all(key.as_bytes()).expect("write embedded key");
}
