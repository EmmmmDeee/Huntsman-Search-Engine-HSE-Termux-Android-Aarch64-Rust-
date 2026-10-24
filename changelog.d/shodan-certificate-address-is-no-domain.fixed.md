- An `ip` lookup with `HUNTSMAN_SHODAN_KEY` set no longer turns a TLS certificate that names an
  address into a domain. A banner whose certificate subject is `192.168.1.1` (common on
  self-signed device certificates) gave a Domain entity `192.168.1.1`, "Name a Shodan banner
  records for the address"; it now gives no pivot. The subject is still listed in
  `tls_subjects`.
