//! The keys a lookup runs with, read once per command from the places `credential-status`
//! reads.

use std::env;
use std::io::Write as _;

use huntsman_recon::environment::HUNTSMAN_HIBP_KEY_ENV;
use huntsman_recon::hibp::key::KeyLoader;
use huntsman_recon::keys::{Keys, Secret};
use huntsman_recon::provider_credentials::secret_for_slot_outside_its_file;

/// The keys every lookup uses: `$HOME/.huntsman.env` and the process environment, the same
/// places `credential-status` reads, so a key it reports as set is never left unused. A
/// skipped default file is named once on stderr, without its values. The warning is a plain
/// write, not `eprintln!`, so a stderr whose reader has gone cannot end the lookup before it
/// saves, or a running `serve`.
pub(super) fn lookup_keys() -> Keys {
    let resolved = Keys::for_lookup(huntsman_recon::environment::home().as_deref());
    if let Some(warning) = resolved.warning {
        let _ = writeln!(std::io::stderr(), "{warning}");
    }
    resolved.keys
}

/// The HIBP key loader for a lookup with `keys`: `HIBP_API_KEY` in the environment, then the
/// `HUNTSMAN_HIBP_KEY` slot from `keys` (the default file, then the environment), then a
/// `HIBP_API_KEY` line in the default file, then `~/.config/hibp/api_key`. `credential-status`
/// finds the same key by the same rule.
pub(super) fn hibp_key_loader(keys: &Keys) -> KeyLoader {
    hibp_key_loader_with(keys, KeyLoader::default_chain)
}

/// [`hibp_key_loader`] with the rest of the chain supplied, so a test can leave out the
/// environment and `~/.config/hibp/api_key`. The slot is read by the rule `credential-status`
/// reports with, except for HIBP's own key file: the chain reads that last itself, so
/// `hibp subscription` names it as the key's source.
fn hibp_key_loader_with(keys: &Keys, chain: impl FnOnce(Option<&str>) -> KeyLoader) -> KeyLoader {
    let slot = secret_for_slot_outside_its_file(keys, HUNTSMAN_HIBP_KEY_ENV);
    chain(slot.as_ref().map(Secret::expose))
}

#[cfg(test)]
mod tests {
    use super::hibp_key_loader_with;
    use huntsman_recon::hibp::key::{KeyLoader, KeyOrigin};
    use huntsman_recon::keys::Keys;

    #[test]
    fn a_file_held_hibp_api_key_reaches_the_loader_as_the_slot() {
        let value = "0123456789abcdef0123456789abcdef";
        let keys = Keys::parse(&format!("HIBP_API_KEY={value}\n")).expect("keys");
        // The environment and `~/.config/hibp/api_key` are left out, so the slot alone decides.
        let (key, origin) =
            hibp_key_loader_with(&keys, |slot| KeyLoader::from_parts(None, slot, None))
                .load()
                .expect("a key credential-status reports as set is used");
        assert_eq!(key.expose(), value);
        assert_eq!(origin, KeyOrigin::HuntsmanSlot);
    }

    /// HIBP's own key file, which `credential-status` counts as the slot's key, reaches the loader
    /// as the file: `hibp subscription` names `file:PATH` as the key's source, not the slot.
    #[cfg(unix)]
    #[test]
    fn hibp_s_own_key_file_reaches_the_loader_as_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let home = std::env::temp_dir().join(format!("hse-hibp-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let file = home.join(".config").join("hibp").join("api_key");
        std::fs::create_dir_all(file.parent().expect("dir")).expect("dir");
        let value = "fedcba9876543210fedcba9876543210";
        std::fs::write(&file, format!("{value}\n")).expect("key");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let keys = Keys::for_lookup(Some(home.as_os_str())).keys;
        let (key, origin) = hibp_key_loader_with(&keys, |slot| {
            KeyLoader::from_parts(None, slot, Some(file.clone()))
        })
        .load()
        .expect("a key");
        // A machine whose environment sets an HIBP key gives the slot that key first, as a
        // lookup's would; otherwise the file is the key, and its source.
        if std::env::var_os("HUNTSMAN_HIBP_KEY").is_none()
            && std::env::var_os("HIBP_API_KEY").is_none()
        {
            assert_eq!(key.expose(), value);
            assert_eq!(origin, KeyOrigin::File(file));
        } else {
            assert_eq!(origin, KeyOrigin::HuntsmanSlot);
        }
        let _ = std::fs::remove_dir_all(&home);
    }
}
