- Text extraction no longer reads a token that merely contains enough digits as a phone
  number. A cookie value such as `GeoIP=US:VA:Ashburn:39.05:-77.49` on an archived page
  became the lead `+61390577494`; a single token is now a phone only when it is written with
  digits, spaces and dialling punctuation alone.
