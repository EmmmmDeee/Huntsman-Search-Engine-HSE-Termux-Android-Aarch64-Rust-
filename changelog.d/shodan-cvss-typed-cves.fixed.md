- A saved scan types each vulnerability by its CVSS score, as Spiderfoot does, so its CRITICAL
  and HIGH vulnerability correlations can fire. Shodan's host record keeps the score of every CVE
  it lists (`cve_scores`), but every CVE became a `VULNERABILITY_GENERAL` element, so no scan ever
  held the `VULNERABILITY_CVE_CRITICAL`, `_HIGH`, `_MEDIUM` or `_LOW` elements the README lists,
  and the shipped `vulnerability_critical`, `vulnerability_high` and `vulnerability_mediumlow`
  rules could never fire: Log4Shell (CVE-2021-44228, 10.0) on a host read as a general finding. A
  CVE a record of the host scores is now typed from 9.0 CRITICAL, from 7.0 HIGH, from 4.0 MEDIUM
  and below LOW, as Spiderfoot's `cveInfo` rates one, wherever the host lists it (InternetDB's
  record too); a CVE nothing scores stays `VULNERABILITY_GENERAL`.
