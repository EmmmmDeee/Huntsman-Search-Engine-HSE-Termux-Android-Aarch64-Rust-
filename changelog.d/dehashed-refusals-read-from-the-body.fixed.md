- A DeHashed refusal now says what DeHashed meant. Before, a rejected key read as "the key's plan
  does not allow this search", an account with no subscription read as "the key was rejected",
  and an authentication failure read as a bad request. DeHashed puts the reason in its error
  body, and one status can mean two things:
  - **403** is "Issue with API Key" (a rejected key, seen live) or "Insufficient Credits".
  - **401** is "You need a search subscription and API credits" or "No Authorization header
    present".
  - **400** is "issue with authentication".

  Each now reads as a rejected key, no subscription or out of credits, so the operator knows
  whether to fix the key or buy credits. The provider's words are matched, never echoed.
