- `people-discover [--region au|us] [--bibliography-only] FULL NAME...` looks for public leads on
  one person by full name, without a key. It runs four site-scoped searches (LinkedIn, GitHub,
  ORCID, and ASIC or SEC pages by region) on each of Bing, Brave and Mojeek, and one Open Library
  author search; `--bibliography-only` asks Open Library alone. The name is sent to each of those
  services. Every result is an unverified lead with its source's typed outcome, never proof of
  identity, and an empty or blocked source is never proof of absence. `POST /api/people/discover`
  runs the same search for a JSON body, guarded like a lookup and one at a time. The web page has
  no form for it.
