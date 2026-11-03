- Which origin a guarded source sends to — the operator's configured value when it is an HTTPS
  origin, the public service when none is set, and one refusal naming the variable when the value
  is set but unusable (so a mistyped origin never silently falls back to the public service) — is
  decided once, by `canonical::configured_https_origin`. The Nominatim and Wikidata legs each had their
  own copy of that decision; both delegate, and the refusal text is unchanged. The rule has its
  own test.
