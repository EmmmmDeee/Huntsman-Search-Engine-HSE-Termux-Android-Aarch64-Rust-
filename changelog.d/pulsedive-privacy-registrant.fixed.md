- A `domain` lookup no longer makes a WHOIS privacy service an organisation. When Pulsedive's
  WHOIS for the domain named a privacy service as the registrant, for example
  `"registrant organization":"Domains By Proxy, LLC"`, that name became an organisation entity
  tied to the domain and an `organisation` attribute on Pulsedive's evidence, so every domain the
  service fronts shared the same organisation. A privacy service's name, judged as the Whoxy
  WHOIS leg already judges one, is now neither. When one of Pulsedive's two WHOIS organisation
  fields is a privacy service and the other names the owner, the owner's is read, and
  `raw_whois` still keeps what Pulsedive wrote.
