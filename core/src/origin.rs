//! Canonical gateway origin check (moved from `gateway-rust/src/config.rs`).

/// lower-case ASCII host, no userinfo, path, query or fragment, and the scheme's default port omitted.
pub fn is_canonical_origin(o: &str) -> bool {
    let (rest, default_port, http) = if let Some(r) = o.strip_prefix("https://") {
        (r, "443", false)
    } else if let Some(r) = o.strip_prefix("http://") {
        (r, "80", true)
    } else {
        return false;
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h, Some(p)),
        _ => (rest, None),
    };
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    let loopback = matches!(host, "localhost" | "127.0.0.1");
    let port_ok = port.is_none_or(|p| {
        p != default_port
            && !p.starts_with('0')
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    });
    host_ok && port_ok && (!http || loopback)
}
