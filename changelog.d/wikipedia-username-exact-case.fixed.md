- The username lookup now asks Wikipedia for the account in the case it was given. A Wikipedia
  account name keeps its case after the first letter, so `JohnDoe` and `Johndoe` are two
  accounts, but the leg asked for the case-folded `johndoe`. A CamelCase handle's edits were
  reported as none, and where the other-cased account existed, its edits were credited to the
  handle. The leg also checks the account the API answered for against the name as `MediaWiki`
  reads it (an underscore is a space, the first letter a capital), and reports another account's
  edits as semantic drift, never as the handle's.
