- An imported WiGLE pair whose decoded API name or token is longer than 4096 bytes is now refused
  by its line, like every other over-long key. Importing
  `sfp_wigle:api_key_encoded=<base64 of "AID:" and a 4097-byte token>` on the Settings page
  answered 422 `a key is at most 4096 bytes`, with no line number. It now answers 422 `nothing
  was imported: line 1: sfp_wigle:api_key_encoded is longer than 4096 bytes`, and names the line
  once even when both parts are too long. Nothing is saved, as before.
