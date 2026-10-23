//! The keys a lookup runs with, read once per command from the places `credential-status`
//! reads.

use std::env;
use std::io::Write as _;

use huntsman_recon::environment::HUNTSMAN_HIBP_KEY_ENV;
use huntsman_recon::hibp::key::KeyLoader;
use huntsman_recon::keys::{Keys, Secret};
use huntsman_recon::provider_credentials::secret_for_slot;

/// The keys every lookup uses: `$HOME/.huntsman.env` and the process environment, the same
/// places `credential-status` reads, so a key it reports as set is never left unused. A
/// skipped default file is named once on stderr, without its values. The warning is a plain
/// write, not `eprintln!`, so a stderr whose reader has gone cannot end the lookup before it
/// saves, or a running `serve`.
pub(super) fn lookup_keys() -> Keys {
    let resolved = Keys::for_lookup(env::var_os("HOME").as_deref());
    if let Some(warning) = resolved.warning {
        let _ = writeln!(std::io::stderr(), "{warning}");
    }
    resolved.keys
}

/// The HIBP key loader for a lookup with `keys`: `HIBP_API_KEY` in the environment, then the
/// `HUNTSMAN_HIBP_KEY` slot from `keys` (the default file, then the environment), then a
/// `HIBP_API_KEY` line in the default file, then `~/.config/hibp/api_key`.
pub(super) fn hibp_key_loader(keys: &Keys) -> KeyLoader {
    hibp_key_loader_with(keys, KeyLoader::default_chain)
}

/// [`hibp_key_loader`] with the rest of the chain supplied, so a test can leave out the
/// environment and `~/.config/hibp/api_key`. The slot is read by the rule `credential-status`
/// reports with.
fn hibp_key_loader_with(keys: &Keys, chain: impl FnOnce(Option<&str>) -> KeyLoader) -> KeyLoader {
    let slot = secret_for_slot(keys, HUNTSMAN_HIBP_KEY_ENV);
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
}
