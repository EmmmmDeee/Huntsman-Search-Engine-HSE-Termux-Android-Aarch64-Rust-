- An RDAP contact telephone published as a tel URI with parameters, such as RFC 9083's own
  `tel:+1-555-555-1234;ext=102`, used to become the Phone entity `+15555551234102`: the
  extension's digits were added to the number, giving one that does not exist. The number now
  ends at the first `;`, so the entity is `+15555551234`. A local number published with a
  `phone-context`, such as `tel:021-234-5679;phone-context=example.nz`, which used to be read as
  the Australian number `+61212345679`, now gives no Phone entity, since its context is not
  applied. The `<role>_phone` attribute on the record still shows the telephone as the registry
  published it, and telephones without parameters do not change.
