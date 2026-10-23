- Two more rules that were written out more than once now have one home each. Output is
  unchanged.
  - ISC, Maltiverse, PhishStats and VirusTotal read a JSON string, number or flag as text with
    `api_leg::scalar`, in place of four private copies of the same rule.
  - Cert Spotter reads a certificate holder's organisation, unit, place and registration with
    `x509::attribute`, the lookup `Certificate::subject_value` makes, so the name on a holder's
    entity and the organisation its certificates are filed under cannot drift apart.
