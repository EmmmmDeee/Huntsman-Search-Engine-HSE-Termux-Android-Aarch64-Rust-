- A network lookup asks OpenCelliD whenever its key is set, whether or not WiGLE credentials are.
  The lookup handed the network legs their transport and keys only when WiGLE was configured or a
  module selection narrowed the run, so with `HUNTSMAN_OPENCELLID_KEY` set and no WiGLE
  credentials, `network cell:…` and `network LAT,LON` (and `scan` routing either) made no request
  and said "no OpenCelliD key configured": the cell site's position and the cell sites around a
  point were never looked up. The network legs now always receive the transport and keys, each
  runs when its own key is set, and a lookup that does not ask a source still sends it nothing.
