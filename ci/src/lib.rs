//! Logic of the CI helper binary, kept in a library so it is unit-tested.
//!
//! Replaces the TypeScript deploy-time scripts of `gateway-workers` (`check-upstream-auth.mjs`,
//! `origin-lock.ts`) so deploying the Rust Worker depends on no TypeScript. The parser is the core's
//! (`access_gate_gateway_core::config::parse_upstream_auth_headers`): the CI check and the Worker agree by
//! construction. The network calls themselves are done by `curl` in the workflows; this crate only
//! validates, prints non-revealing diagnostics and classifies.

use access_gate_gateway_core::config::{parse_upstream_auth_headers, AuthHeader};

/// Whether `s` is exactly `n` lower-case hexadecimal digits.
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
            t.len() == 48
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// The result of checking a secret: diagnostics (never a value) and the number of shape problems.
pub struct AuthCheck {
    /// Diagnostics about each header: lengths and shape notes, never a value.
    pub lines: Vec<String>,
    /// How many headers have a shape the Cloudflare Access service token does not have.
    pub shape_problems: usize,
    /// The parsed headers (the credential, for the callers that need it; never printed).
    pub headers: Vec<AuthHeader>,
}

/// Parse `UPSTREAM_AUTH_HEADERS` with the Worker's own parser and check the Cloudflare Access
/// service-token headers' shape. A malformed value, or no headers at all, is an error.
pub fn check_upstream_auth(raw: Option<&str>) -> anyhow::Result<AuthCheck> {
    // The same parser the Worker uses at start-up, so CI accepts exactly what the Worker accepts; its errors name the entry, never the value.
    let headers = parse_upstream_auth_headers(raw)?;
    if headers.is_empty() {
        // An empty list would deploy a Worker that cannot pass the origin lock.
        anyhow::bail!("UPSTREAM_AUTH_HEADERS has no headers");
    }
    // The lines to print, and how many headers have a shape the service token does not have.
    let mut lines = Vec::new();
    let mut shape_problems = 0;
    // One diagnostic line per header.
    for h in &headers {
        // Report only facts about the value (its length and shape), never the value, because this goes to a public CI log.
        let mut notes = vec![format!("length {}", h.value.chars().count())];
        // A common paste mistake that the origin rejects with no useful message.
        if h.value != h.value.trim() {
            notes.push("leading/trailing whitespace".to_string());
        }
        // Another paste mistake: the whole `Name: value` line was pasted as the value.
        if h.value.contains(": ") || h.value.contains(":\t") {
            notes.push("contains \": \" (a whole header line pasted as the value?)".to_string());
        }
        // Header names are case-insensitive, so match on the lower-case name; other headers have no known shape.
        let shape = match h.name.to_ascii_lowercase().as_str() {
            "cf-access-client-id" => {
                Some((client_id_shape_ok(&h.value), "<32 hex>.access (39 chars)"))
            }
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
        // The name is safe to print; the value is not.
        lines.push(format!("  {}: {}", h.name, notes.join(", ")));
    }
    // The count last, so the log ends with the total.
    lines.push(format!(
        "UPSTREAM_AUTH_HEADERS: {} header(s)",
        headers.len()
    ));
    Ok(AuthCheck {
        lines,
        shape_problems,
        headers,
    })
}

/// A curl config file body that sends `headers` (`header = "Name: value"` per line, escaped), so the
/// secret never appears on a command line.
pub fn curl_config(headers: &[AuthHeader]) -> String {
    // curl config strings are double-quoted, so a backslash or a quote in the value must be escaped.
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    headers
        .iter()
        // One `header = "Name: value"` line per header, read by `curl --config`.
        .map(|h| format!("header = \"{}: {}\"\n", esc(&h.name), esc(&h.value)))
        .collect()
}

/// Response headers parsed from a `curl -D` dump (the last response block; names lower-cased).
pub fn parse_header_dump(dump: &str) -> Vec<(String, String)> {
    // Only the headers of the last response are kept: `curl -D` writes one block per redirect hop.
    let mut block: Vec<(String, String)> = Vec::new();
    for line in dump.lines() {
        let line = line.trim_end_matches('\r');
        // A status line starts a new response block, so earlier hops are dropped.
        if line.starts_with("HTTP/") {
            block.clear();
        } else if let Some((k, v)) = line.split_once(':') {
            // Names are lower-cased so look-ups do not depend on how the origin spells them.
            block.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    block
}

/// The value of a header, matched case-insensitively.
fn get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        // An empty header counts as absent.
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
    // `cf-access-domain` is added only by Cloudflare Access, so its presence says who rejected the request.
    let via = if get(headers, "cf-access-domain").is_some() {
        " (rejected by Cloudflare Access)"
    } else {
        ""
    };
    let mut out = vec![format!("Origin check {host}: HTTP {status}{via}")];
    if get(headers, "cf-mitigated") == Some("challenge") {
        // A challenge says nothing about the origin, so warn and let the deploy continue rather than fail on a runner the zone distrusts.
        out.push("::warning::Origin check inconclusive: the zone challenged this runner (Bot Fight Mode). Verify the live route after the deploy.".to_string());
        return (out, false);
    }
    if (200..300).contains(&status) {
        return (out, false);
    }
    for h in [
        "server",
        "cf-mitigated",
        "cf-access-domain",
        // Headers that help the operator see who answered; none of them carries a credential.
        "www-authenticate",
    ] {
        if let Some(v) = get(headers, h) {
            out.push(format!("  {h}: {v}"));
        }
    }
    // The page title tells an Access login page from the origin's own error page.
    if let Some(title) = page_title(body) {
        out.push(format!("  page title: {title}"));
    }
    out.push("::error::The origin rejected UPSTREAM_AUTH_HEADERS; not deploying.".to_string());
    (out, true)
}

/// The `<title>` of an HTML page, to tell a login page from the origin.
fn page_title(body: &str) -> Option<String> {
    // Search a lower-cased copy, but cut the title from the original so its case is kept.
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title>")? + "<title>".len();
    let end = start + lower.get(start..)?.find("</title>")?;
    let t = body.get(start..end)?.trim();
    // Print only a short, plain title: a long or markup-bearing one is not worth putting in a log.
    (t.len() <= 120 && !t.contains('<')).then(|| t.to_string())
}

/// The scheduled negative origin check (audit F32): what counts as "refused by Cloudflare Access".
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OriginLock {
    /// The origin refused the request without the lock's credential: the lock holds.
    Locked,
    /// The origin answered without the credential: the lock is open.
    Open,
    /// The answer does not tell either way: the zone challenged the runner (Bot Fight Mode) before Access saw the request.
    Inconclusive,
}

impl OriginLock {
    /// The result as the word the workflow prints.
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
    // Accept an absolute URL, a scheme-relative `//host/path`, or a path, resolved against the reserved host `origin.invalid`.
    let (host, path) = if let Some(rest) = location
        .split_once("://")
        .map(|(_, r)| r)
        .or_else(|| location.strip_prefix("//"))
    {
        let (auth, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
        // Cut the query and fragment off the authority part.
        let auth = auth.split(['?', '#']).next().unwrap_or("");
        let host = auth
            // Drop any `user@` so only the host is compared.
            .rsplit('@')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        (host.to_ascii_lowercase(), format!("/{path}"))
    } else if location.starts_with('/') {
        ("origin.invalid".to_string(), location.to_string())
    } else {
        ("origin.invalid".to_string(), format!("/{location}"))
    };
    (host, path)
}

/// Classify an origin's answer to a request made without the lock's credential. A 401 or 403 from Cloudflare Access (it names `cf-access-domain`) or a redirect to the Access login means locked; a 401, 403 or redirect from anywhere else, or a 2xx, means open; a zone challenge (`cf-mitigated: challenge`) proves nothing; any other status (a 404 or a 5xx, say) is not a refusal by Access, so it counts as open.
pub fn classify_origin_response(status: u16, headers: &[(String, String)]) -> (OriginLock, String) {
    // Bot Fight Mode can challenge a CI runner before Access sees it. That proves nothing either way.
    if get(headers, "cf-mitigated") == Some("challenge") {
        return (
            OriginLock::Inconclusive,
            format!("HTTP {status}, the zone challenged this client (cf-mitigated: challenge)"),
        );
    }
    // A refusal is only proof of the lock when Access itself made it.
    if status == 401 || status == 403 {
        return if get(headers, "cf-access-domain").is_some() {
            (
                OriginLock::Locked,
                format!("HTTP {status} from Cloudflare Access"),
            )
        } else {
            (
                OriginLock::Open,
                format!(
                    "HTTP {status} but not from Cloudflare Access (no cf-access-domain header)"
                ),
            )
        };
    }
    // A redirect to the Access login is how a browser-oriented Access application refuses an unauthenticated request.
    if (300..400).contains(&status) {
        let (host, path) = location_parts(get(headers, "location").unwrap_or(""));
        let to_access =
            // Either form of the Access login address counts.
            host.ends_with(".cloudflareaccess.com") || path.starts_with("/cdn-cgi/access/");
        return if to_access {
            (
                OriginLock::Locked,
                format!("HTTP {status} redirect to the Access login"),
            )
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
            // The worst case: the origin served content to a caller with no credential.
            format!("HTTP {status}: the origin answered a request without the service token"),
        );
    }
    (
        OriginLock::Open,
        // Anything else (404, 5xx) was not a refusal by Access, so the lock cannot be shown to hold.
        format!("HTTP {status}: not an Access refusal"),
    )
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// A well-shaped client id: 32 lower-case hex digits and `.access`.
    const ID: &str = "0123456789abcdef0123456789abcdef.access";
    /// A well-shaped client secret in the current form: `cfast_` and 48 characters.
    const SECRET_NEW: &str = "cfast_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";

    /// Header pairs as owned strings, the form the parsing functions take.
    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The `UPSTREAM_AUTH_HEADERS` JSON for a service token with this id and secret.
    fn raw(id: &str, secret: &str) -> String {
        format!(
            r#"[{{"name":"CF-Access-Client-Id","value":"{id}"}},{{"name":"CF-Access-Client-Secret","value":"{secret}"}}]"#
        )
    }

    /// Access header shapes.
    #[test]
    fn access_header_shapes() {
        // The accepted shape.
        assert!(client_id_shape_ok(ID));
        // Missing the `.access` suffix.
        assert!(!client_id_shape_ok("0123456789abcdef0123456789abcdef"));
        assert!(!client_id_shape_ok(
            // Upper-case hex is refused: the real ids are lower case.
            "0123456789ABCDEF0123456789abcdef.access"
        ));
        assert!(client_secret_shape_ok(SECRET_NEW));
        // The older secret form: 64 hex digits.
        assert!(client_secret_shape_ok(&"a".repeat(64)));
        assert!(!client_secret_shape_ok("cfast_short"));
        // Right length but not hex.
        assert!(!client_secret_shape_ok(&"g".repeat(64)));
    }

    /// A well formed secret passes and nothing secret is printed.
    #[test]
    fn a_well_formed_secret_passes_and_nothing_secret_is_printed() {
        let c = check_upstream_auth(Some(&raw(ID, SECRET_NEW))).unwrap();
        assert_eq!(c.shape_problems, 0);
        let all = c.lines.join("\n");
        assert!(
            all.contains("CF-Access-Client-Id: length 39, shape ok"),
            "{all}"
        );
        assert!(all.contains("2 header(s)"));
        // The log lines must not contain either value.
        assert!(!all.contains(ID) && !all.contains(SECRET_NEW));
    }

    /// Bad shapes are counted and whitespace is noted.
    #[test]
    fn bad_shapes_are_counted_and_whitespace_is_noted() {
        // Both values are wrong: one has whitespace, the other is too short.
        let c = check_upstream_auth(Some(&raw(" nope", "short"))).unwrap();
        assert_eq!(c.shape_problems, 2);
        let all = c.lines.join("\n");
        assert!(all.contains("leading/trailing whitespace") && all.contains("unexpected shape"));
        // A secret that looks like a pasted header line.
        let pasted = check_upstream_auth(Some(&raw(ID, "x: y"))).unwrap();
        assert!(pasted.lines.join("\n").contains("whole header line pasted"));
    }

    /// The core parser rules apply.
    #[test]
    fn the_core_parser_rules_apply() {
        for bad in [
            "",
            "[]",
            // A header line instead of JSON.
            "CF-Access-Client-Id: abc",
            // An object where a list is required.
            r#"{"name":"a","value":"b"}"#,
            // A header name with a space is not a valid name.
            r#"[{"name":"Bad Name","value":"b"}]"#,
        ] {
            assert!(check_upstream_auth(Some(bad)).is_err(), "{bad:?}");
        }
        assert!(check_upstream_auth(None).is_err());
    }

    /// The curl config escapes and keeps secrets off the command line.
    #[test]
    fn the_curl_config_escapes_and_keeps_secrets_off_the_command_line() {
        let hs = vec![AuthHeader {
            name: "X".into(),
            value: "a\"b\\c".into(),
        }];
        // The quote and the backslash are both escaped.
        assert_eq!(curl_config(&hs), "header = \"X: a\\\"b\\\\c\"\n");
    }

    /// The dump keeps the last response block.
    #[test]
    fn the_dump_keeps_the_last_response_block() {
        let d = "HTTP/2 302\r\nLocation: /x\r\n\r\nHTTP/2 403\r\nServer: cloudflare\r\nCF-Access-Domain: o.example\r\n\r\n";
        let hs = parse_header_dump(d);
        assert_eq!(get(&hs, "server"), Some("cloudflare"));
        // The first response (a redirect) is dropped.
        assert_eq!(get(&hs, "location"), None);
        assert_eq!(get(&hs, "cf-access-domain"), Some("o.example"));
    }

    /// The origin report fails on a rejection and warns on a challenge.
    #[test]
    fn the_origin_report_fails_on_a_rejection_and_warns_on_a_challenge() {
        // A 2xx means the origin accepted the credentials: one line, no failure.
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
        assert!(
            all.contains("(rejected by Cloudflare Access)")
                && all.contains("page title: Forbidden")
        );
        // The `::error::` prefix makes GitHub Actions show the line as an annotation.
        assert!(all.contains("::error::The origin rejected UPSTREAM_AUTH_HEADERS; not deploying."));
        let (l, fail) =
            report_origin_check("o.example", 403, &h(&[("cf-mitigated", "challenge")]), "");
        assert!(!fail && l.join("\n").contains("::warning::"));
    }

    // The cases of gateway-workers/test/origin-lock.test.ts, one for one.
    /// Access 401 or 403 is locked.
    #[test]
    fn access_401_or_403_is_locked() {
        for s in [401, 403] {
            let (st, _) = classify_origin_response(
                s,
                &h(&[(
                    "cf-access-domain",
                    "walrus-storage-relay-origin.example.com",
                )]),
            );
            assert_eq!(st, OriginLock::Locked);
        }
    }

    /// A redirect to the access login is locked.
    #[test]
    fn a_redirect_to_the_access_login_is_locked() {
        let a = h(&[(
            "location",
            "https://team.cloudflareaccess.com/cdn-cgi/access/login/x?kid=1",
        )]);
        assert_eq!(classify_origin_response(302, &a).0, OriginLock::Locked);
        let b = h(&[("location", "/cdn-cgi/access/login/x")]);
        assert_eq!(classify_origin_response(302, &b).0, OriginLock::Locked);
    }

    /// A refusal that is not access is open.
    #[test]
    fn a_refusal_that_is_not_access_is_open() {
        assert_eq!(classify_origin_response(401, &[]).0, OriginLock::Open);
        assert_eq!(
            classify_origin_response(403, &h(&[("server", "cloudflare")])).0,
            OriginLock::Open
        );
    }

    /// A redirect elsewhere any 2xx 404 and 5xx are open.
    #[test]
    fn a_redirect_elsewhere_any_2xx_404_and_5xx_are_open() {
        let elsewhere = h(&[("location", "https://elsewhere.example.com/")]);
        assert_eq!(
            classify_origin_response(302, &elsewhere).0,
            OriginLock::Open
        );
        assert_eq!(classify_origin_response(301, &[]).0, OriginLock::Open);
        assert_eq!(classify_origin_response(200, &[]).0, OriginLock::Open);
        assert_eq!(
            classify_origin_response(200, &h(&[("cf-access-domain", "x")])).0,
            OriginLock::Open
        );
        assert_eq!(classify_origin_response(404, &[]).0, OriginLock::Open);
        assert_eq!(classify_origin_response(502, &[]).0, OriginLock::Open);
    }

    /// A zone challenge proves nothing.
    #[test]
    fn a_zone_challenge_proves_nothing() {
        assert_eq!(
            classify_origin_response(403, &h(&[("cf-mitigated", "challenge")])).0,
            OriginLock::Inconclusive
        );
    }
}
