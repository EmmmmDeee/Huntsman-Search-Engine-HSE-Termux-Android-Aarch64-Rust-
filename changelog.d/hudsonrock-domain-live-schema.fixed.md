- The Hudson Rock Cavalier leg of a domain lookup (`hudsonrock`) reads the answer the endpoint
  gives. It looked for `total_employees` and `total_users`, which the endpoint does not send: it
  answers with `employees`, `users`, `third_parties` and `total` (verified 2026-10-31), so every
  domain's row failed as schema drift and no exposure was ever reported. A domain's row now says
  how many of its employees, users and third parties infostealers compromised, when an employee and
  a user were last compromised, and the stealer families with how many compromises each took, most
  first; all three counts zero is a validated zero. A host is asked as the domain it is registered
  under, which its row names: Cavalier holds its counts by registrable domain and answers all zero
  for a host below one (`www.tesla.com` zero, `tesla.com` its counts). The URLs the stolen
  credentials were for, the password-strength figures and the antivirus list stay unread, as the
  credentials always were. A `404` from the endpoint is now a failed row, not "no exposure": the
  host answers `404` for a path it does not serve, as it would after the endpoint moved, while the
  email leg already read it so.
