//! The keys a lookup runs with, read once per command from the places `credential-status`
//! reads.

use std::env;

use huntsman_recon::environment::HUNTSMAN_HIBP_KEY_ENV;
use huntsman_recon::hibp::key::KeyLoader;
use huntsman_recon::keys::{Keys, Secret};

/// The keys every lookup uses: `$HOME/.huntsman.env` and the process environment, the same
/// places `credential-status` reads, so a key it reports as set is never left unused. A
/// skipped default file is named once on stderr, without its values.
pub(super) fn lookup_keys() -> Keys {
    let resolved = Keys::for_lookup(env::var_os("HOME").as_deref());
    if let Some(warning) = resolved.warning {
        eprintln!("{warning}");
    }
    resolved.keys
}

/// The HIBP key loader for a lookup with `keys`: `HIBP_API_KEY`, then the `HUNTSMAN_HIBP_KEY`
/// slot from `keys` (the default file, then the environment), then `~/.config/hibp/api_key`.
pub(super) fn hibp_key_loader(keys: &Keys) -> KeyLoader {
    let slot = keys.get(HUNTSMAN_HIBP_KEY_ENV);
    KeyLoader::default_chain(slot.as_ref().map(Secret::expose))
}
