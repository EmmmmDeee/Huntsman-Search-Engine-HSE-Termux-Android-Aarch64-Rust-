- Keys-file rules that were written out twice now have one home each. Output is unchanged.
  - The `HUNTSMAN_HIBP_KEY` slot's `HIBP_API_KEY` alias is one table,
    `provider_credentials::SLOT_FALLBACKS`, which both `secret_for_slot` and the key import read.
  - The private-file gate behind `~/.huntsman.env` and the HIBP and DeHashed `api_key` files reads
    through `fsio`'s bounded read, with `fsio`'s I/O error and refusal texts.
  - `doctor` bounds its read of `~/.huntsman.env` with the keys file's own size limit.
