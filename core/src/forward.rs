//! Forwarding policy, independent of how a platform moves bytes: which requests may be forwarded and
//! how a failed forward is answered. The platform's [`crate::gateway::Upstream`] applies it around
//! its own I/O (a buffered hyper request natively, a streamed `fetch` in a Worker), so both answer the
//! same status for the same fault.
//!
//! Policy: only `GET`, `HEAD`, `POST` and `PUT` are forwarded (405 otherwise); the path must be free
//! of encoded separators and dot segments (400); a declared `Content-Length` over the cap is refused
//! before any byte is read (413), as is a body that exceeds it while being read; a body that does not
//! arrive within `BODY_READ_TIMEOUT_SECS` is 408. Redirects are never followed (the service-token
//! headers must not follow a `Location`): an upstream 3xx is a 502. The whole exchange is bounded by
//! `UPSTREAM_TIMEOUT_SECS` (504).

use crate::headers::is_safe_path;

/// Methods the gateway forwards; anything else is refused with 405 before any work is done.
pub const FORWARDED_METHODS: [&str; 4] = ["GET", "HEAD", "POST", "PUT"];

/// True if `method` may be forwarded to the upstream.
pub fn is_forwarded_method(method: &str) -> bool {
    FORWARDED_METHODS.contains(&method)
}

/// A request the gateway answers itself instead of forwarding: status and client-visible reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub reason: &'static str,
}

pub const METHOD_NOT_ALLOWED: Refusal = Refusal {
    status: 405,
    reason: "method not allowed",
};
pub const INVALID_PATH: Refusal = Refusal {
    status: 400,
    reason: "invalid path",
};
pub const BODY_TOO_LARGE: Refusal = Refusal {
    status: 413,
    reason: "request body too large",
};
pub const BODY_TIMED_OUT: Refusal = Refusal {
    status: 408,
    reason: "request body timed out",
};
pub const UPSTREAM_TIMED_OUT: Refusal = Refusal {
    status: 504,
    reason: "upstream timed out",
};
pub const UPSTREAM_ERROR: Refusal = Refusal {
    status: 502,
    reason: "upstream error",
};

/// True when the request declares a `Content-Length` above `max`: rejected before reading. A missing
/// or unparseable length is left to the capped read, never rejected here.
pub fn declared_too_large(content_length: Option<&str>, max: usize) -> bool {
    content_length
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > max as u64)
}

/// The checks that precede reading the body or contacting the upstream, in order: method (405),
/// path (400), declared body size (413).
pub fn preflight(
    method: &str,
    path: &str,
    content_length: Option<&str>,
    max_body_bytes: usize,
) -> Result<(), Refusal> {
    if !is_forwarded_method(method) {
        return Err(METHOD_NOT_ALLOWED);
    }
    if !is_safe_path(path) {
        return Err(INVALID_PATH);
    }
    if declared_too_large(content_length, max_body_bytes) {
        return Err(BODY_TOO_LARGE);
    }
    Ok(())
}

/// True for an upstream 3xx. A relay has no business redirecting, and refusing one also covers an
/// Access login redirect after the service token expires. Nothing from such a response is passed on.
pub fn is_redirect(status: u16) -> bool {
    (300..400).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_length_over_cap_is_rejected_up_front() {
        assert!(declared_too_large(Some("1001"), 1000));
        assert!(declared_too_large(Some(" 1001 "), 1000));
        assert!(!declared_too_large(Some("1000"), 1000));
        // No or unparseable length: left to the capped read, never rejected here.
        assert!(!declared_too_large(None, 1000));
        assert!(!declared_too_large(Some("abc"), 1000));
    }

    #[test]
    fn preflight_checks_method_then_path_then_size() {
        assert_eq!(preflight("POST", "/v1/x", Some("10"), 1000), Ok(()));
        assert_eq!(
            preflight("DELETE", "/a/../b", Some("9999"), 1000),
            Err(METHOD_NOT_ALLOWED)
        );
        assert_eq!(
            preflight("POST", "/a/../b", Some("9999"), 1000),
            Err(INVALID_PATH)
        );
        assert_eq!(preflight("PUT", "/a//b", None, 1000), Err(INVALID_PATH));
        assert_eq!(
            preflight("PUT", "/ok", Some("9999"), 1000),
            Err(BODY_TOO_LARGE)
        );
        for m in ["GET", "HEAD", "POST", "PUT"] {
            assert!(is_forwarded_method(m), "{m}");
        }
        for m in ["DELETE", "PATCH", "OPTIONS", "get", "TRACE", "CONNECT"] {
            assert!(!is_forwarded_method(m), "{m}");
        }
    }

    #[test]
    fn redirects_are_the_3xx_range() {
        assert!(is_redirect(301) && is_redirect(302) && is_redirect(399));
        assert!(!is_redirect(200) && !is_redirect(299) && !is_redirect(400));
    }
}
