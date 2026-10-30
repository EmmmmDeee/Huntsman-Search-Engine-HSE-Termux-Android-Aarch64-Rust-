- A BSSID's manufacturer, read offline from the IEEE OUI registry, no longer counts as a source
  that observed the address. The network lookup's `oui` reading of a BSSID's own prefix was the one
  offline reading a lookup runs over its target that counted as corroboration, unlike an e-mail's
  parts, a handle's variants and a number's plan. So a BSSID WiGLE recorded counted two
  independent sources, which raised its effective confidence and let the high-corroboration
  correlation (AU-003) hold it as corroborated, and one nothing recorded counted the registry as
  its observer. Every offline reading a lookup runs over its target is now checked to be
  enrichment, never a source.
