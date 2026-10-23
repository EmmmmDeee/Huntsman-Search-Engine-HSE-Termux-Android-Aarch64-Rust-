- A Canadian phone number now names Canada wherever a number's country is read; it was named the
  United States. The Spiderfoot `COUNTRY_NAME` that is derived from a phone number, as
  `sfp_countryname` derives it, used to give every `+1` number outside the Caribbean list the US.
  Canada's area codes now sit in the one dialling-prefix table that `phone`, the NANP reading and
  Spiderfoot's country derivation all read. The table that held the Caribbean codes a second
  time is gone, and a bare `+1` fallback now reads "United States" rather than "NANP (US /
  Canada)".
