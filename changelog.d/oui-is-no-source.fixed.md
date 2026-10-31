- A BSSID's manufacturer, read offline from the IEEE OUI registry, and what a domain's namespace
  requires of whoever holds a name in it (its registry policy: `.gov.au` names only for government
  bodies, `.id.au` only for people, `.edu.vn` only for schools) no longer count as sources that
  observed the address or the name. Both are readings of the value itself, as an e-mail's parts, a
  handle's variants and a number's plan already were, but they counted as corroboration. So a
  BSSID WiGLE recorded counted two independent sources, which raised its effective confidence and
  let the high-corroboration correlation (AU-003) hold it as corroborated, and one nothing recorded
  counted the registry as its observer; a `.gov.au` or `.id.au` name the resolvers alone found did
  the same. A test now holds every record each lookup writes to a module the lookup asks or a
  reading that observes no one.
