- A PhishStats report that names no address (its `ip` missing, null or blank) is refused
  instead of counting as a phishing URL reported on the queried address, which it would have
  tagged malicious with nothing but the server-side filter to bind it. Each report's address is
  now compared as an address, so a report naming the queried IPv6 address in another spelling
  (`2001:DB8:0:0::1` for `2001:db8::1`) is kept rather than refused as another address.
