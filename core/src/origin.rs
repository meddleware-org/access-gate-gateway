//! Canonical gateway origin check, and origin comparison for the request-loop guard.

/// True if `o` is a canonical origin: `https://host[:port]` (or `http://` for a loopback host), a
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

/// The `scheme://host[:port]` prefix of an http(s) URL in canonical form: scheme and host
/// lower-cased, the scheme's default port dropped (what `new URL(u).origin` yields), so two
/// spellings of one origin compare equal.
pub fn normalized_origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let authority = match authority.strip_suffix(default_port) {
        Some(host) if !default_port.is_empty() => host,
        _ => authority.as_str(),
    };
    format!("{scheme}://{authority}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_origin_rules() {
        for ok in [
            "https://a.example",
            "https://a.example:8443",
            "http://localhost:8787",
            "http://127.0.0.1:3000",
        ] {
            assert!(is_canonical_origin(ok), "{ok}");
        }
        for bad in [
            "https://a.example:443",
            "https://a.example/x",
            "https://a.example?x",
            "http://a.example",
            "https://",
            "https://a b",
            "https://A.example",
            "https://a.example:0443",
            "https://a.example:99999",
            "https://[::1]",
            "ftp://a.example",
            "a.example",
        ] {
            assert!(!is_canonical_origin(bad), "{bad}");
        }
    }

    #[test]
    fn normalized_origin_drops_case_path_and_default_port() {
        for (url, want) in [
            ("https://a.example", "https://a.example"),
            ("https://A.Example/x/y?z=1#f", "https://a.example"),
            ("HTTPS://a.example:443/x", "https://a.example"),
            ("https://a.example:8443/x", "https://a.example:8443"),
            ("http://a.example:80", "http://a.example"),
            ("http://a.example:443", "http://a.example:443"),
            ("https://a.example:80", "https://a.example:80"),
        ] {
            assert_eq!(normalized_origin(url), want, "{url}");
        }
    }
}
