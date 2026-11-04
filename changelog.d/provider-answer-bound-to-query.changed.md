- One rule now decides whether a provider answer is about the identifier that was queried:
  `api_leg::bound_to_query`. The answer must name its own identifier (present and non-blank)
  and the source's comparison must accept it, or it is refused as "answer names no …" or
  "answer names another …". Numverify (exact E.164 digits), the Hunter email verifier
  (case-insensitive address) and PhishStats (each report's IP, compared as an address) use it in
  place of three hand-written checks, with the same outcomes.
