//! Logic of the CI helper binary, kept in a library so it is unit-tested.
//!
//! Replaces the TypeScript deploy-time scripts of `gateway-workers` (`check-upstream-auth.mjs`,
//! `origin-lock.ts`) so deploying the Rust Worker depends on no TypeScript. The parser is the core's
//! (`nft_gate_core::config::parse_upstream_auth_headers`): the CI check and the Worker agree by
//! construction. The network calls themselves are done by `curl` in the workflows; this crate only
//! validates, prints non-revealing diagnostics and classifies.

use nft_gate_core::config::{parse_upstream_auth_headers, AuthHeader};

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `<32 hex>.access`.
pub fn client_id_shape_ok(v: &str) -> bool {
    v.strip_suffix(".access").is_some_and(|h| is_hex(h, 32))
}

/// `cfast_<48 of [A-Za-z0-9_-]>` (tokens from 2026-08-26) or the older `<64 hex>`.
pub fn client_secret_shape_ok(v: &str) -> bool {
    is_hex(v, 64)
        || v.strip_prefix("cfast_").is_some_and(|t| {
            t.len() == 48 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// The result of checking a secret: diagnostics (never a value) and the number of shape problems.
pub struct AuthCheck {
    pub lines: Vec<String>,
    pub shape_problems: usize,
    pub headers: Vec<AuthHeader>,
}

/// Parse `UPSTREAM_AUTH_HEADERS` with the Worker's own parser and check the Cloudflare Access
/// service-token headers' shape. A malformed value, or no headers at all, is an error.
pub fn check_upstream_auth(raw: Option<&str>) -> anyhow::Result<AuthCheck> {
    let headers = parse_upstream_auth_headers(raw)?;
    if headers.is_empty() {
        anyhow::bail!("UPSTREAM_AUTH_HEADERS has no headers");
    }
    let mut lines = Vec::new();
    let mut shape_problems = 0;
    for h in &headers {
        let mut notes = vec![format!("length {}", h.value.chars().count())];
        if h.value != h.value.trim() {
            notes.push("leading/trailing whitespace".to_string());
        }
        if h.value.contains(": ") || h.value.contains(":\t") {
            notes.push("contains \": \" (a whole header line pasted as the value?)".to_string());
        }
        let shape = match h.name.to_ascii_lowercase().as_str() {
            "cf-access-client-id" => Some((client_id_shape_ok(&h.value), "<32 hex>.access (39 chars)")),
            "cf-access-client-secret" => Some((
                client_secret_shape_ok(&h.value),
                "cfast_<48 alnum> (54 chars) or <64 hex>",
            )),
            _ => None,
        };
        if let Some((ok, want)) = shape {
            if ok {
                notes.push("shape ok".to_string());
            } else {
                notes.push(format!("unexpected shape, want {want}"));
                shape_problems += 1;
            }
        }
        lines.push(format!("  {}: {}", h.name, notes.join(", ")));
    }
    lines.push(format!("UPSTREAM_AUTH_HEADERS: {} header(s)", headers.len()));
    Ok(AuthCheck {
        lines,
        shape_problems,
        headers,
    })
}

/// A curl config file body that sends `headers` (`header = "Name: value"` per line, escaped), so the
/// secret never appears on a command line.
pub fn curl_config(headers: &[AuthHeader]) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    headers
        .iter()
        .map(|h| format!("header = \"{}: {}\"\n", esc(&h.name), esc(&h.value)))
        .collect()
}

/// Response headers parsed from a `curl -D` dump (the last response block; names lower-cased).
pub fn parse_header_dump(dump: &str) -> Vec<(String, String)> {
    let mut block: Vec<(String, String)> = Vec::new();
    for line in dump.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("HTTP/") {
            block.clear();
        } else if let Some((k, v)) = line.split_once(':') {
            block.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    block
}

fn get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

/// The origin check after the deploy-time probe: prints who rejected, and says whether to fail.
/// `Ok` lines are for the log; the bool is "fail the deploy".
pub fn report_origin_check(
    host: &str,
    status: u16,
    headers: &[(String, String)],
    body: &str,
) -> (Vec<String>, bool) {
    let via = if get(headers, "cf-access-domain").is_some() {
        " (rejected by Cloudflare Access)"
    } else {
        ""
    };
    let mut out = vec![format!("Origin check {host}: HTTP {status}{via}")];
    if get(headers, "cf-mitigated") == Some("challenge") {
        out.push("::warning::Origin check inconclusive: the zone challenged this runner (Bot Fight Mode). Verify the live route after the deploy.".to_string());
        return (out, false);
    }
    if (200..300).contains(&status) {
        return (out, false);
    }
    for h in ["server", "cf-mitigated", "cf-access-domain", "www-authenticate"] {
        if let Some(v) = get(headers, h) {
            out.push(format!("  {h}: {v}"));
        }
    }
    if let Some(title) = page_title(body) {
        out.push(format!("  page title: {title}"));
    }
    out.push("::error::The origin rejected UPSTREAM_AUTH_HEADERS; not deploying.".to_string());
    (out, true)
}

fn page_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title>")? + "<title>".len();
    let end = start + lower.get(start..)?.find("</title>")?;
    let t = body.get(start..end)?.trim();
    (t.len() <= 120 && !t.contains('<')).then(|| t.to_string())
}

/// The scheduled negative origin check (audit F32): what counts as "refused by Cloudflare Access".
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OriginLock {
    Locked,
    Open,
    Inconclusive,
}

impl OriginLock {
    pub fn as_str(self) -> &'static str {
        match self {
            OriginLock::Locked => "locked",
            OriginLock::Open => "open",
            OriginLock::Inconclusive => "inconclusive",
        }
    }
}

/// `host` and `path` of a `Location` value resolved against `https://origin.invalid`.
fn location_parts(location: &str) -> (String, String) {
    let (host, path) = if let Some(rest) = location
        .split_once("://")
        .map(|(_, r)| r)
        .or_else(|| location.strip_prefix("//"))
    {
        let (auth, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
        let auth = auth.split(['?', '#']).next().unwrap_or("");
        let host = auth.rsplit('@').next().unwrap_or("").split(':').next().unwrap_or("");
        (host.to_ascii_lowercase(), format!("/{path}"))
    } else if location.starts_with('/') {
        ("origin.invalid".to_string(), location.to_string())
    } else {
        ("origin.invalid".to_string(), format!("/{location}"))
    };
    (host, path)
}

pub fn classify_origin_response(status: u16, headers: &[(String, String)]) -> (OriginLock, String) {
    // Bot Fight Mode can challenge a CI runner before Access sees it. That proves nothing either way.
    if get(headers, "cf-mitigated") == Some("challenge") {
        return (
            OriginLock::Inconclusive,
            format!("HTTP {status}, the zone challenged this client (cf-mitigated: challenge)"),
        );
    }
    if status == 401 || status == 403 {
        return if get(headers, "cf-access-domain").is_some() {
            (OriginLock::Locked, format!("HTTP {status} from Cloudflare Access"))
        } else {
            (
                OriginLock::Open,
                format!("HTTP {status} but not from Cloudflare Access (no cf-access-domain header)"),
            )
        };
    }
    if (300..400).contains(&status) {
        let (host, path) = location_parts(get(headers, "location").unwrap_or(""));
        let to_access = host.ends_with(".cloudflareaccess.com") || path.starts_with("/cdn-cgi/access/");
        return if to_access {
            (OriginLock::Locked, format!("HTTP {status} redirect to the Access login"))
        } else {
            (
                OriginLock::Open,
                format!("HTTP {status} redirect that does not go to the Access login"),
            )
        };
    }
    if (200..300).contains(&status) {
        return (
            OriginLock::Open,
            format!("HTTP {status}: the origin answered a request without the service token"),
        );
    }
    (OriginLock::Open, format!("HTTP {status}: not an Access refusal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef.access";
    const SECRET_NEW: &str = "cfast_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn raw(id: &str, secret: &str) -> String {
        format!(
            r#"[{{"name":"CF-Access-Client-Id","value":"{id}"}},{{"name":"CF-Access-Client-Secret","value":"{secret}"}}]"#
        )
    }

    #[test]
    fn access_header_shapes() {
        assert!(client_id_shape_ok(ID));
        assert!(!client_id_shape_ok("0123456789abcdef0123456789abcdef"));
        assert!(!client_id_shape_ok("0123456789ABCDEF0123456789abcdef.access"));
        assert!(client_secret_shape_ok(SECRET_NEW));
        assert!(client_secret_shape_ok(&"a".repeat(64)));
        assert!(!client_secret_shape_ok("cfast_short"));
        assert!(!client_secret_shape_ok(&"g".repeat(64)));
    }

    #[test]
    fn a_well_formed_secret_passes_and_nothing_secret_is_printed() {
        let c = check_upstream_auth(Some(&raw(ID, SECRET_NEW))).unwrap();
        assert_eq!(c.shape_problems, 0);
        let all = c.lines.join("\n");
        assert!(all.contains("CF-Access-Client-Id: length 39, shape ok"), "{all}");
        assert!(all.contains("2 header(s)"));
        assert!(!all.contains(ID) && !all.contains(SECRET_NEW));
    }

    #[test]
    fn bad_shapes_are_counted_and_whitespace_is_noted() {
        let c = check_upstream_auth(Some(&raw(" nope", "short"))).unwrap();
        assert_eq!(c.shape_problems, 2);
        let all = c.lines.join("\n");
        assert!(all.contains("leading/trailing whitespace") && all.contains("unexpected shape"));
        let pasted = check_upstream_auth(Some(&raw(ID, "x: y"))).unwrap();
        assert!(pasted.lines.join("\n").contains("whole header line pasted"));
    }

    #[test]
    fn the_core_parser_rules_apply() {
        for bad in [
            "",
            "[]",
            "CF-Access-Client-Id: abc",
            r#"{"name":"a","value":"b"}"#,
            r#"[{"name":"Bad Name","value":"b"}]"#,
        ] {
            assert!(check_upstream_auth(Some(bad)).is_err(), "{bad:?}");
        }
        assert!(check_upstream_auth(None).is_err());
    }

    #[test]
    fn the_curl_config_escapes_and_keeps_secrets_off_the_command_line() {
        let hs = vec![AuthHeader {
            name: "X".into(),
            value: "a\"b\\c".into(),
        }];
        assert_eq!(curl_config(&hs), "header = \"X: a\\\"b\\\\c\"\n");
    }

    #[test]
    fn the_dump_keeps_the_last_response_block() {
        let d = "HTTP/2 302\r\nLocation: /x\r\n\r\nHTTP/2 403\r\nServer: cloudflare\r\nCF-Access-Domain: o.example\r\n\r\n";
        let hs = parse_header_dump(d);
        assert_eq!(get(&hs, "server"), Some("cloudflare"));
        assert_eq!(get(&hs, "location"), None);
        assert_eq!(get(&hs, "cf-access-domain"), Some("o.example"));
    }

    #[test]
    fn the_origin_report_fails_on_a_rejection_and_warns_on_a_challenge() {
        let (l, fail) = report_origin_check("o.example", 200, &[], "");
        assert!(!fail && l.len() == 1);
        let (l, fail) = report_origin_check(
            "o.example",
            403,
            &h(&[("cf-access-domain", "x"), ("server", "cloudflare")]),
            "<html><title> Forbidden </title>",
        );
        let all = l.join("\n");
        assert!(fail);
        assert!(all.contains("(rejected by Cloudflare Access)") && all.contains("page title: Forbidden"));
        assert!(all.contains("::error::The origin rejected UPSTREAM_AUTH_HEADERS; not deploying."));
        let (l, fail) = report_origin_check("o.example", 403, &h(&[("cf-mitigated", "challenge")]), "");
        assert!(!fail && l.join("\n").contains("::warning::"));
    }

    // The cases of gateway-workers/test/origin-lock.test.ts, one for one.
    #[test]
    fn access_401_or_403_is_locked() {
        for s in [401, 403] {
            let (st, _) = classify_origin_response(s, &h(&[("cf-access-domain", "walrus-relay-origin.example.com")]));
            assert_eq!(st, OriginLock::Locked);
        }
    }

    #[test]
    fn a_redirect_to_the_access_login_is_locked() {
        let a = h(&[("location", "https://team.cloudflareaccess.com/cdn-cgi/access/login/x?kid=1")]);
        assert_eq!(classify_origin_response(302, &a).0, OriginLock::Locked);
        let b = h(&[("location", "/cdn-cgi/access/login/x")]);
        assert_eq!(classify_origin_response(302, &b).0, OriginLock::Locked);
    }

    #[test]
    fn a_refusal_that_is_not_access_is_open() {
        assert_eq!(classify_origin_response(401, &[]).0, OriginLock::Open);
        assert_eq!(classify_origin_response(403, &h(&[("server", "cloudflare")])).0, OriginLock::Open);
    }

    #[test]
    fn a_redirect_elsewhere_any_2xx_404_and_5xx_are_open() {
        let elsewhere = h(&[("location", "https://elsewhere.example.com/")]);
        assert_eq!(classify_origin_response(302, &elsewhere).0, OriginLock::Open);
        assert_eq!(classify_origin_response(301, &[]).0, OriginLock::Open);
        assert_eq!(classify_origin_response(200, &[]).0, OriginLock::Open);
        assert_eq!(classify_origin_response(200, &h(&[("cf-access-domain", "x")])).0, OriginLock::Open);
        assert_eq!(classify_origin_response(404, &[]).0, OriginLock::Open);
        assert_eq!(classify_origin_response(502, &[]).0, OriginLock::Open);
    }

    #[test]
    fn a_zone_challenge_proves_nothing() {
        assert_eq!(
            classify_origin_response(403, &h(&[("cf-mitigated", "challenge")])).0,
            OriginLock::Inconclusive
        );
    }
}
