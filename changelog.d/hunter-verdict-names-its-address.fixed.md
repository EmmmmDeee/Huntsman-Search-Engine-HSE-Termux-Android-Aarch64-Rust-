- A Hunter email-verifier answer that names no address (the `email` field missing, null, empty
  or blank) is refused instead of being credited to the address that was asked about. Before,
  only an answer naming a different address was refused, so a verdict, its SMTP checks and its
  public pages could become evidence for an address the answer never mentioned.
