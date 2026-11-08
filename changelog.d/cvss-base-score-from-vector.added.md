- The `cve` triage can now derive CVSS severity from a vector string when NVD did not answer (its
  keyless tier is rate-limited) but OSV returned a `CVSS:3.1/...` vector. A new offline `cvss`
  module computes the CVSS v3.0/v3.1 base score and severity band from the vector, matching the
  FIRST specification's weights and Roundup rule. The triage keeps a severity signal from a vector
  alone, so a rate-limited NVD no longer blanks it.
