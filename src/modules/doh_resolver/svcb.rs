//! HTTPS/SVCB record (RFC 9460) `ipv4hint`/`ipv6hint` extraction.

/// Extract the `ipv4hint` / `ipv6hint` addresses from an HTTPS/SVCB record
/// (RFC 9460) as returned in a DoH JSON `data` field. **Pure**, fully
/// bounds-checked — malformed input yields whatever parsed cleanly, never a
/// panic. Handles BOTH forms the two resolvers emit: dns.google's friendly
/// presentation string (`1 . alpn=h3,h2 ipv4hint=A,B ipv6hint=C,D`), and
/// cloudflare-dns's raw RFC 3597 generic form (`\# <len> <hex octets>`), which
/// carries the SvcParams as binary and must be decoded on the wire.
///
/// The hint addresses are the origin/edge IPs a client is told to connect to —
/// infrastructure that an A/AAAA lookup may not surface (e.g. an HTTP/3-only or
/// ECH-fronted endpoint), so a new one is a real pivot.
pub(super) fn parse_svcb_hints(data: &str) -> Vec<String> {
    let data = data.trim();
    if let Some(hex_body) = data.strip_prefix(r"\#") {
        return svcb_hints_from_wire(hex_body);
    }
    // Friendly presentation form: whitespace-separated params, comma-lists.
    let mut out = Vec::new();
    for tok in data.split_whitespace() {
        if let Some(list) = tok
            .strip_prefix("ipv4hint=")
            .or_else(|| tok.strip_prefix("ipv6hint="))
        {
            out.extend(
                list.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    out
}

/// Parse the binary SVCB RDATA behind an RFC 3597 `\#`-prefixed generic record
/// (the space-separated `<decimal length> <hex octets…>` body) and return the
/// `ipv4hint` (SvcParamKey 4) and `ipv6hint` (key 6) addresses. Every read is
/// length-checked, so a truncated or hostile record simply stops early. **Pure.**
fn svcb_hints_from_wire(hex_body: &str) -> Vec<String> {
    let mut toks = hex_body.split_whitespace();
    // First token is the RFC 3597 decimal rdata length; we bound on the actual
    // decoded bytes instead, so skip it. The rest are hex octets.
    toks.next();
    let mut bytes: Vec<u8> = Vec::new();
    for t in toks {
        match u8::from_str_radix(t, 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return Vec::new(), // non-hex octet → malformed, bail
        }
    }

    let mut out = Vec::new();
    // SvcPriority (2 octets).
    let mut i = 2usize;
    if bytes.len() < i {
        return out;
    }
    // TargetName: length-prefixed labels terminated by a zero-length octet.
    while i < bytes.len() {
        let label_len = bytes[i] as usize;
        i += 1;
        if label_len == 0 {
            break; // root / end of name
        }
        i = i.saturating_add(label_len);
        if i > bytes.len() {
            return out;
        }
    }
    // SvcParams: repeated (key:2, len:2, value:len).
    while i + 4 <= bytes.len() {
        let key = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        let vlen = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        i += 4;
        if i + vlen > bytes.len() {
            break;
        }
        let value = &bytes[i..i + vlen];
        match key {
            4 => {
                for c in value.chunks_exact(4) {
                    out.push(std::net::Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string());
                }
            }
            6 => {
                for c in value.chunks_exact(16) {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(c);
                    out.push(std::net::Ipv6Addr::from(o).to_string());
                }
            }
            _ => {}
        }
        i += vlen;
    }
    out
}
