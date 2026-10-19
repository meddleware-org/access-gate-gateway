//! Durable Object shard routing. Wire-compatible with the TypeScript Worker's live state: the shard
//! tags, the `<shard>.<hex>` nonce form and the instance names (`nonce:<shard>`, `nonce:redeem`) are
//! the same, so a deploy over the live script keeps finding its nonces, rate windows and redemptions.

/// The shard tags a nonce may carry: Cloudflare's continent codes (lower-cased) plus `g` (global).
/// Anything else was not issued by this gateway, and routing on it would let a client mint Durable
/// Object instances at will.
pub const NONCE_SHARDS: [&str; 8] = ["af", "an", "as", "eu", "na", "oc", "sa", "g"];

/// The fixed instance for redemptions (the consume digest carries no region tag).
pub const REDEEM_SHARD: &str = "redeem";

/// The shard tag embedded in a `<shard>.<hex>` nonce so a later `take` routes back to the issuing
/// shard even under anycast drift: the prefix, `g` when there is no dot, `None` when the prefix is not
/// a known shard (the nonce is then invalid).
pub fn shard_of_nonce(nonce: &str) -> Option<&str> {
    match nonce.find('.') {
        None | Some(0) => Some("g"),
        Some(dot) => {
            let shard = nonce.get(..dot)?;
            NONCE_SHARDS.contains(&shard).then_some(shard)
        }
    }
}

/// The region tag for a request: `g` in global mode, else the lower-cased `cf.continent` when it is a
/// known shard, else `g`.
pub fn region_of(global: bool, continent: Option<&str>) -> String {
    if global {
        return "g".to_string();
    }
    match continent.map(str::to_ascii_lowercase) {
        Some(c) if NONCE_SHARDS.contains(&c.as_str()) => c,
        _ => "g".to_string(),
    }
}

/// The Durable Object instance name of a shard.
pub fn instance_name(shard: &str) -> String {
    format!("nonce:{shard}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_only_known_continent_shards_and_the_global_shard() {
        assert_eq!(shard_of_nonce("eu.abc"), Some("eu"));
        assert_eq!(shard_of_nonce("g.abc"), Some("g"));
        assert_eq!(shard_of_nonce("abc"), Some("g"));
        assert_eq!(shard_of_nonce(".abc"), Some("g"));
        assert_eq!(shard_of_nonce("zz.abc"), None);
        assert_eq!(shard_of_nonce("EU.abc"), None); // issued tags are lower-case
        assert_eq!(shard_of_nonce("attacker-shard-1.deadbeef"), None);
    }

    #[test]
    fn region_follows_the_continent_unless_global() {
        assert_eq!(region_of(false, Some("EU")), "eu");
        assert_eq!(region_of(false, Some("T1")), "g"); // Tor
        assert_eq!(region_of(false, None), "g");
        assert_eq!(region_of(true, Some("EU")), "g");
        assert_eq!(instance_name("eu"), "nonce:eu");
    }
}
