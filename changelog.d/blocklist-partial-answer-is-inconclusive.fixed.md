- A DNS blocklist or filtering resolver that answered only in part is no longer reported as not
  listing a subject. A source asked through several zones or filters (UCEPROTECT's levels 1 to 3,
  AdGuard's default and family filters, CleanBrowsing's security, adult and family filters,
  Cloudflare's malware and family filters) gave a validated zero ("not listed", "not blocked")
  when at least one of them answered, even when another did not answer, missed its test point or
  answered with an error. So with UCEPROTECT's level 1 timing out, levels 2 and 3, which list an
  address's network and AS, made the address read as on none of UCEPROTECT's lists, and with
  Cloudflare's malware filter answering HTTP 503, its family filter not blocking a name made
  Cloudflare read as not blocking it. Such a row is now inconclusive and names what each zone or
  filter said; a listing on one that answered is still the source's finding, and a source none of
  whose zones or filters answered still says why. One rule now joins the row of every source
  asked through several endpoints, the rule the threat feeds already followed.
