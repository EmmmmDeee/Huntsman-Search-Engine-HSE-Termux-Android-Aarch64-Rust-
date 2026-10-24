- `credential_origin::AuthenticationAuthority::credential_slot`,
  `AuthenticationAuthority::provider_id` and `fetch::Credential::provider_id`, which nothing
  called outside their own tests. A `fetch::Credential` still takes the operator's approval to be
  built, and no longer keeps it, since only `provider_id` read it. No output changes.
