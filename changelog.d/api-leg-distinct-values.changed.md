- Provider decoders that build a list attribute from a repeated field — the values in the order
  first seen, each once — share one `api_leg::Distinct` (and `api_leg::distinct` for the cleaned
  case) instead of eight private copies: the `distinct` functions of URLhaus, LeakIX, Netlas and
  Robtex and the `Distinct` structs of OTX, crt.sh, HackerTarget and urlscan. Each provider keeps
  its own rule for what counts as the same value (exact text, text ignoring ASCII case for
  HackerTarget hosts and Robtex names, or cleaned text), so every finding reads as before; the
  shared type has its own unit test.
