- `security-tools` collects four security checks in one CLI. `catalog` lists the nine supported
  tool workflows and the gaps in each, offline. `sha256-audit` checks a local word list against
  one unsalted SHA-256 digest without printing any candidate. `headers` reads an HTTPS site's
  security response headers. `paths --authorized` makes up to 16 anonymous HTTPS GET probes,
  150 ms apart, that the operator declares they are authorised to make. It is CLI only.
