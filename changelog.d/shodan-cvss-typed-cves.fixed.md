- A saved scan types each vulnerability by its CVSS score, as Spiderfoot does, so its CRITICAL
  and HIGH vulnerability correlations can fire. Shodan's host record keeps the score of every CVE
  it lists (`cve_scores`), but every CVE became a `VULNERABILITY_GENERAL` element, so no scan ever
  held the `VULNERABILITY_CVE_CRITICAL`, `_HIGH`, `_MEDIUM` or `_LOW` elements the README lists,
  and the shipped `vulnerability_critical` and `vulnerability_high` rules could never fire:
  Log4Shell (CVE-2021-44228, 10.0) on a host read as a general finding, and a host with two or
  more CVEs raised only the MEDIUM `vulnerability_mediumlow` correlation, which counts general
  findings, whatever their scores. A CVE any record of the scan scores is now typed from 9.0
  CRITICAL, from 7.0 HIGH, from 4.0 MEDIUM and below LOW, as Spiderfoot's `cveInfo` rates one,
  wherever it is listed and on every host (a host only InternetDB lists too); a CVE nothing scores
  stays `VULNERABILITY_GENERAL`.
