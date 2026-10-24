- IPQualityScore's `N/A`, its word for a field it has no value for, is no longer kept as a
  number's carrier, line type or place, or an address's network or place. A `phone` lookup whose
  answer had `"carrier":"N/A"` gave an Organisation entity `N/A`, which tied every number IPQS
  could not place to the same organisation, and kept `carrier`, `line_type` and `region` as `N/A`
  (exported as `PROVIDER_TELCO` and `PHONE_NUMBER_TYPE` `N/A`). An `ip` lookup kept `N/A` as the
  ISP, organisation, country, city, region and time zone. Each such field is now left out, as the
  postcode already was.
