//! Client identity for rate limiting. The IP is a rate-limit KEY, never an authenticator.
//!
//! Each platform finds its client address its own way (the TCP peer plus `X-Forwarded-For` natively,
//! `CF-Connecting-IP` on Cloudflare); the shaping of that address into a bucket key is shared here.

use std::net::{IpAddr, Ipv6Addr};

/// The client IP used as the pre-auth rate-limit key, from the `X-Forwarded-For` field values
/// (each possibly a comma list, in order) and the TCP peer.
///
/// With `trusted_hops == 0` it is the TCP peer address: forwarding headers are client-controlled
/// and would let anyone pick a fresh rate-limit bucket per request. With N trusted proxies in
/// front, each appends the address it saw, so the Nth entry from the right is the address the
/// outermost trusted proxy received the request from. A header with fewer entries did not pass
/// through every proxy, so the peer address is used instead.
pub fn client_ip(xff: &[&str], peer: Option<IpAddr>, trusted_hops: usize) -> String {
    rate_key(&client_ip_raw(xff, peer, trusted_hops))
}

/// IPv6 clients are keyed by their /64 (one subscriber controls the whole prefix and could
/// otherwise rotate source addresses to dodge the limit and grow the limiter); IPv4 and anything
/// unparseable are used as is.
pub fn rate_key(ip: &str) -> String {
    match ip.parse::<Ipv6Addr>() {
        Ok(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Err(_) => ip.to_string(),
    }
}

fn client_ip_raw(xff: &[&str], peer: Option<IpAddr>, trusted_hops: usize) -> String {
    let peer_ip = || peer.map_or_else(|| "unknown".to_string(), |p| p.to_string());
    if trusted_hops == 0 {
        return peer_ip();
    }
    let entries: Vec<&str> = xff
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    match entries.len().checked_sub(trusted_hops) {
        Some(i) => entries[i].to_string(),
        None => peer_ip(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_ignores_forwarding_headers_without_trusted_proxies() {
        let peer: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(client_ip(&["1.2.3.4"], Some(peer), 0), "198.51.100.7");
        assert_eq!(client_ip(&[], None, 0), "unknown");
    }

    #[test]
    fn client_ip_takes_the_entry_the_outermost_trusted_proxy_saw() {
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        // client spoofed "6.6.6.6"; the one trusted proxy appended the real client 203.0.113.9.
        assert_eq!(
            client_ip(&["6.6.6.6, 203.0.113.9"], Some(peer), 1),
            "203.0.113.9"
        );
        // two hops: CDN appended the client, ingress appended the CDN edge.
        assert_eq!(
            client_ip(&["6.6.6.6, 203.0.113.9, 172.16.0.1"], Some(peer), 2),
            "203.0.113.9"
        );
        // several header fields are one list, in order.
        assert_eq!(
            client_ip(&["6.6.6.6", "203.0.113.9, 172.16.0.1"], Some(peer), 2),
            "203.0.113.9"
        );
        // fewer entries than hops: fall back to the peer.
        assert_eq!(client_ip(&["203.0.113.9"], Some(peer), 2), "10.0.0.2");
    }

    #[test]
    fn ipv6_clients_are_keyed_by_their_slash_64() {
        assert_eq!(
            rate_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            rate_key("2001:db8:1:2::1")
        );
        assert_ne!(rate_key("2001:db8:1:2::1"), rate_key("2001:db8:1:3::1"));
        assert_eq!(rate_key("203.0.113.9"), "203.0.113.9");
        assert_eq!(rate_key("unknown"), "unknown");
    }
}
