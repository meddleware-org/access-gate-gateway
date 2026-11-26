//! `access-gate-gateway-ci`: the helpers the deploy and origin-lock workflows call.
//!
//! ```text
//! access-gate-gateway-ci check-upstream-auth [--curl-config FILE]
//!     Validates $UPSTREAM_AUTH_HEADERS with the core's parser; prints non-revealing diagnostics; exits 1
//!     on a malformed value or a Cloudflare Access header of the wrong shape. With --curl-config it
//!     writes a curl config (mode 0600) so the workflow can probe the origin without the secret on a
//!     command line.
//! access-gate-gateway-ci report-origin-check --url URL --status N [--headers FILE] [--body FILE]
//!     The verdict on that probe (the workflow ran curl): exits 1 when the origin rejected the headers.
//! access-gate-gateway-ci classify-origin --status N [--headers FILE]
//!     Prints `locked|open|inconclusive <detail>` for a probe WITHOUT the service token (origin lock).
//! ```
//! No value is ever printed.

use access_gate_gateway_ci::{
    check_upstream_auth, classify_origin_response, curl_config, parse_header_dump,
    report_origin_check,
};
use std::process::ExitCode;

/// The value after `--name` in the arguments.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Read a file, or standard input when no path is given.
fn read(path: Option<String>) -> String {
    path.and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default()
}

/// Parse the HTTP status the workflow passes in.
fn status(args: &[String]) -> Result<u16, String> {
    flag(args, "--status")
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| "--status N is required".to_string())
}

/// The host of a URL, for the diagnostics (never the whole URL).
fn host_of(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_string()
}

/// Write the file with mode 0600 because it holds the service-token headers. A file that already exists is truncated and rewritten, and keeps the mode it has.
#[cfg(unix)]
fn write_private(path: &str, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body.as_bytes())
}

/// Write the file with the platform's default permissions: there is no owner-only mode to request without Unix permissions.
#[cfg(not(unix))]
fn write_private(path: &str, body: &str) -> std::io::Result<()> {
    std::fs::write(path, body)
}

/// Run one subcommand; `Ok(true)` is a pass, `Ok(false)` a failed check, `Err` a usage error.
fn run(args: &[String]) -> Result<bool, String> {
    match args.first().map(String::as_str) {
        // Validate the secret and, when asked, write the curl config the later steps use.
        Some("check-upstream-auth") => {
            let raw = std::env::var("UPSTREAM_AUTH_HEADERS").ok();
            let check = check_upstream_auth(raw.as_deref()).map_err(|e| e.to_string())?;
            for l in &check.lines {
                println!("{l}");
            }
            if check.shape_problems > 0 {
                println!(
                    "::error::{} Cloudflare Access header value(s) do not have the documented shape; not deploying.",
                    check.shape_problems
                );
                return Ok(false);
            }
            if let Some(path) = flag(args, "--curl-config") {
                write_private(&path, &curl_config(&check.headers)).map_err(|e| e.to_string())?;
            }
            Ok(true)
        }
        // Explain a rejected deploy-time probe (who rejected it) and decide whether to fail the deploy.
        Some("report-origin-check") => {
            let url = flag(args, "--url").ok_or("--url is required")?;
            let headers = parse_header_dump(&read(flag(args, "--headers")));
            let (lines, fail) = report_origin_check(
                &host_of(&url),
                status(args)?,
                &headers,
                &read(flag(args, "--body")),
            );
            for l in lines {
                println!("{l}");
            }
            Ok(!fail)
        }
        // Print `locked|open|inconclusive` for the scheduled negative check; the workflow decides what to do with the word, so this always exits 0.
        Some("classify-origin") => {
            let headers = parse_header_dump(&read(flag(args, "--headers")));
            let (state, detail) = classify_origin_response(status(args)?, &headers);
            println!("{} {detail}", state.as_str());
            Ok(true)
        }
        _ => Err(
            "usage: access-gate-gateway-ci check-upstream-auth|report-origin-check|classify-origin"
                .into(),
        ),
    }
}

/// Run the subcommand and turn the outcome into the exit code the workflow step reads: 0 pass, 1 failed check or usage error.
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            // The error text never contains a header value (the core's messages name the index only).
            println!("::error::{e}");
            ExitCode::from(1)
        }
    }
}
