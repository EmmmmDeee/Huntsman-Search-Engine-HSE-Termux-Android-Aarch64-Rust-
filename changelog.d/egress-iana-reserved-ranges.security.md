- Public-only egress (the default for every provider fetch) no longer connects to address space
  IANA has not assigned for global use: IPv6 outside the assignable unicast range `2000::/3`
  through `2cff::/16` (the reserved `2d00::/8`–`3fff::/16`, `3ffe::`, `4000::` and the like),
  and the deprecated 6to4 relay block `192.88.99.0/24`. A network that routes reserved space
  internally could otherwise be reached through a hostname that resolves into it. An IPv4
  address carried in a mapped, NAT64 or 6to4 IPv6 form is still judged as that IPv4 address,
  and `Unrestricted` egress for an authorised lab or LAN is unchanged.
