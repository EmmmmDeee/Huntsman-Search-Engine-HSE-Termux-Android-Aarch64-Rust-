- DeHashed results now show every value a breach record holds, as OathNet's already do, and the
  account's search credits left. Passwords, hashes and salts are still never shown.
  - **What changed.** DeHashed's leg used to keep only the database name, record counts and
    username or address pivots. It now reads each record as DeHashed's v2 documentation shapes
    it, through the one rule both breach legs follow (`breach_record`).
  - **Fields shown.** Names, phone numbers, addresses, IP addresses, dates of birth, companies,
    URLs, social handles, cryptocurrency addresses, licence plates and VINs, within the same
    bounds.
  - **Credentials.** A password, a hash, a hash type or a salt is kept by field name only.
  - **Where each place shows it:**
    - `exposure` adds the exposed field types to each `dehashed_breach` row and a
      `dehashed_value` row per value, keeps them as `value_<field>` evidence, and notes the
      credits left.
    - `dehashed search` prints `balance=` and `took=`, then each record's values, exposed fields
      and `unstructured` or `le_only` flags.
    - `dehashed search --save-artifact` keeps the values as evidence and the credits left as the
      receipt's quota.
  - **Metadata types.** `balance`, `took` and `total` are read leniently, so an odd type on a
    metadata field never loses the answer.
