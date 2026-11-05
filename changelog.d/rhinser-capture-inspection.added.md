- Rhinser capture inspection grows in three ways, all offline and read-only:
  - A capture may now carry `tlv` events. They are read by the same bounded BER-TLV inspector
    as `osint nfc tlv`, which never keeps raw card values.
  - `osint native --entities FILE` previews an inspected capture as candidate fixture-event
    entities. Each is capped at candidate confidence and tagged `candidate` and `derived`, and
    none claims a real device, card or owner.
  - The web UI imports and inspects a capture through `POST /api/rhinser/native`. The route
    answers only on a loopback bind and refuses a body over the form limit with 413. The panel
    can export the redacted report.
