//! What the Worker answers: one plain value (status, a mutable header map, a body) that every path
//! produces, so CORS and the `Vary` header are applied in exactly one place and every answer, error
//! paths included, goes through it.

use crate::cors::grants;
use wasm_bindgen::JsValue;

/// A response body.
pub enum Body {
    Empty,
    Text(String),
    /// The upstream's body, passed through untouched (never buffered).
    Stream(web_sys::ReadableStream),
}

pub struct Out {
    pub status: u16,
    pub headers: web_sys::Headers,
    pub body: Body,
}

impl Out {
    fn new(status: u16, body: Body) -> Result<Self, JsValue> {
        Ok(Self {
            status,
            headers: web_sys::Headers::new()?,
            body,
        })
    }

    /// A gateway answer: JSON with the TypeScript Worker's content type.
    pub fn json(status: u16, body: String, allow: Option<&str>) -> Result<Self, JsValue> {
        let out = Self::new(status, Body::Text(body))?;
        out.headers.set("content-type", "application/json")?;
        if let Some(a) = allow {
            out.headers.set("allow", a)?;
        }
        Ok(out)
    }

    /// `{"error": reason}`.
    pub fn error(status: u16, reason: &str) -> Result<Self, JsValue> {
        Self::json(
            status,
            crate::json::render(&serde_json::json!({ "error": reason })),
            None,
        )
    }

    /// `/healthz`: the runtime's default text content type.
    pub fn text(status: u16, body: &str) -> Result<Self, JsValue> {
        Self::new(status, Body::Text(body.to_string()))
    }

    /// The CORS preflight answer (the grants are added by [`finish`]).
    pub fn preflight() -> Result<Self, JsValue> {
        Self::new(204, Body::Empty)
    }
}

/// Apply the CORS policy and build the response. Only the gateway's own policy applies: the upstream
/// response was already stripped of every `access-control-*` field (`drop_response_header`).
pub fn finish(out: Out, allowed_origin: Option<&str>) -> Result<web_sys::Response, JsValue> {
    if let Some(o) = allowed_origin {
        out.headers.set("access-control-allow-origin", o)?;
    }
    // The ACAO value depends on the request Origin, so any cache in front must key on it.
    out.headers.append("vary", "Origin")?;
    for (k, v) in grants() {
        out.headers.set(k, v)?;
    }
    let init = web_sys::ResponseInit::new();
    init.set_status(out.status);
    init.set_headers(&out.headers);
    match &out.body {
        Body::Empty => web_sys::Response::new_with_opt_str_and_init(None, &init),
        Body::Text(t) => web_sys::Response::new_with_opt_str_and_init(Some(t), &init),
        Body::Stream(s) => web_sys::Response::new_with_opt_readable_stream_and_init(Some(s), &init),
    }
}
