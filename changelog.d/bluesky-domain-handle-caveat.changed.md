- When a Bluesky profile uses a custom domain as its handle, the domain `username` reports now
  says what that proves: the AT Protocol checked DNS or web-root control (a `_atproto` TXT record
  or `/.well-known/atproto-did`) while the handle was in force. It also says what it does not
  prove: who registered the domain. Subdomain handles an operator issued need separate
  corroboration.
