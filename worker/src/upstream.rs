//! The streamed upstream proxy: the core's [`Upstream`] port over `fetch`.
//!
//! The body is never buffered. Chunks stay in JS-land (the counter reads `byteLength` and re-enqueues
//! the same `Uint8Array`), so wasm linear memory does not grow with a 100 MB upload. Policy is the
//! core's: `forward::preflight` (405 / 400 / 413 on a declared length), the request/response header
//! lists, `is_redirect` (an upstream 3xx is a 502, redirects are never followed), the `Via` marker.
//! Parity with `gateway-workers/src/proxy.ts` and its tests.

use crate::config::WorkerConfig;
use crate::out::{Body, Out};
use access_gate_gateway_core::forward::{
    is_redirect, preflight, Refusal, BODY_TOO_LARGE, UPSTREAM_ERROR, UPSTREAM_TIMED_OUT,
};
use access_gate_gateway_core::gateway::{ForwardKind, Upstream};
use access_gate_gateway_core::headers::{
    connection_named, drop_request_header, drop_response_header, VIA_TOKEN,
};
use js_sys::{Array, Function, Object, Reflect};
use std::cell::Cell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortController, ReadableStream, TransformStream};

/// The incoming request plus the parts of its URL the proxy needs.
pub struct ProxyRequest {
    /// The incoming request.
    pub req: web_sys::Request,
    /// Its path.
    pub path: String,
    /// `?a=b` or empty.
    pub search: String,
}

/// The upstream port: forwards a verified request to the protected origin.
pub struct WorkerUpstream<'a> {
    /// The configuration.
    pub cfg: &'a WorkerConfig,
    /// The execution context.
    pub ctx: &'a worker::Context,
}

/// Convert a JavaScript value to text.
fn js(e: JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

/// Answer with a refusal.
fn refusal(r: Refusal) -> Out {
    Out::error(r.status, r.reason).unwrap_or_else(|_| fallback(r.status))
}

/// Constructing a `Headers` object cannot realistically fail; if it does the only thing left is an
/// answer with no headers.
fn fallback(status: u16) -> Out {
    Out {
        status,
        headers: web_sys::Headers::new()
            .unwrap_or_else(|_| JsCast::unchecked_into(JsValue::UNDEFINED)),
        body: Body::Empty,
    }
}

/// `(name, value)` pairs of a `Headers` (names lower-case; duplicates already combined by the runtime).
pub fn header_entries(h: &web_sys::Headers) -> Vec<(String, String)> {
    let Ok(Some(it)) = js_sys::try_iter(h) else {
        return Vec::new();
    };
    it.filter_map(Result::ok)
        .filter_map(|e| {
            let pair = Array::from(&e);
            Some((pair.get(0).as_string()?, pair.get(1).as_string()?))
        })
        .collect()
}

/// Call a JavaScript method with one argument.
fn call(target: &JsValue, name: &str, arg: &JsValue) {
    // Look the method up by name, so the code needs no generated binding for the stream controller.
    if let Ok(f) = Reflect::get(target, &name.into()) {
        if let Some(f) = f.dyn_ref::<Function>() {
            let _ = f.call1(target, arg);
        }
    }
}

/// Pass `body` through unchanged while counting bytes; once the running total exceeds `max`, mark
/// `exceeded`, abort the upstream request and error the stream. The transform closure is owned by the
/// task that waits for the pipe to finish (no `forget`, no leak, never dropped while the pipe runs).
fn limit_body(
    body: &ReadableStream,
    max: f64,
    exceeded: Rc<Cell<bool>>,
    abort: AbortController,
) -> Result<ReadableStream, JsValue> {
    let seen = Rc::new(Cell::new(0f64));
    let transform =
        Closure::<dyn FnMut(JsValue, JsValue)>::new(move |chunk: JsValue, controller: JsValue| {
            // Read only the chunk's length: the bytes themselves are never copied into wasm memory.
            let len = Reflect::get(&chunk, &"byteLength".into())
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            // Running total of the bytes seen so far.
            seen.set(seen.get() + len);
            if seen.get() > max {
                exceeded.set(true);
                abort.abort();
                call(
                    &controller,
                    "error",
                    &JsValue::from_str("request body too large"),
                );
                return;
            }
            // Pass the same chunk on unchanged.
            call(&controller, "enqueue", &chunk);
        });
    let transformer = Object::new();
    Reflect::set(&transformer, &"transform".into(), transform.as_ref())?;
    let ts = TransformStream::new_with_transformer(&transformer)?;
    // The pipe rejects when the counter errors the stream; the consumer sees that through `readable`.
    // Connect the client body to the counter.
    let piped = body.pipe_to(&ts.writable());
    wasm_bindgen_futures::spawn_local(async move {
        let _ = JsFuture::from(piped).await;
        drop(transform);
    });
    Ok(ts.readable())
}

/// Re-attach the declared length (a transform stream has none) so the upstream still gets a
/// Content-Length-framed body rather than a chunked one.
fn fixed_length(readable: &ReadableStream, len: u32) -> Result<ReadableStream, JsValue> {
    // A fixed-length stream tells the runtime the exact size, so it sends `Content-Length` and not chunked encoding.
    let fls = worker::worker_sys::FixedLengthStream::new(len)?;
    let pair = Object::new();
    Reflect::set(
        &pair,
        &"readable".into(),
        &Reflect::get(&fls, &"readable".into())?,
    )?;
    Reflect::set(
        &pair,
        &"writable".into(),
        &Reflect::get(&fls, &"writable".into())?,
    )?;
    Ok(readable.pipe_through(pair.unchecked_ref()))
}

/// `AbortSignal.any([a, b])`.
fn any_signal(
    a: &web_sys::AbortSignal,
    b: &web_sys::AbortSignal,
) -> Result<web_sys::AbortSignal, JsValue> {
    // `AbortSignal.any` has no typed binding, so it is called through reflection.
    let ctor = Reflect::get(&js_sys::global(), &"AbortSignal".into())?;
    let any: Function = Reflect::get(&ctor, &"any".into())?.dyn_into()?;
    let list = Array::of2(a, b);
    any.call1(&ctor, &list)?.dyn_into()
}

impl WorkerUpstream<'_> {
    /// One exchange with the upstream for `req`, with `search` as the forwarded query string.
    async fn send(&self, p: &ProxyRequest, search: &str) -> Out {
        let cfg = &self.cfg.core;
        let method = p.req.method();
        let has_body = method != "GET" && method != "HEAD";
        let headers_in = p.req.headers();
        // The declared length is only read for methods that carry a body.
        let cl = if has_body {
            headers_in.get("content-length").ok().flatten()
        } else {
            None
        };
        // Refuse a bad method, an unsafe path or an over-size declared length before any byte is read or sent.
        if let Err(r) = preflight(&method, &p.path, cl.as_deref(), cfg.max_body_bytes) {
            return refusal(r);
        }
        match self
            .exchange(p, search, &method, has_body, cl.as_deref())
            .await
        {
            Ok(out) => out,
            Err(e) => {
                // The detail goes to the Worker log; the client only sees the generic upstream error.
                worker::console_error!("upstream exchange failed: {e}");
                refusal(UPSTREAM_ERROR)
            }
        }
    }

    /// Send the request upstream within the deadline and apply the response policy.
    async fn exchange(
        &self,
        p: &ProxyRequest,
        search: &str,
        method: &str,
        has_body: bool,
        cl: Option<&str>,
    ) -> Result<Out, String> {
        let cfg = &self.cfg.core;
        // Set by the body counter when the upload passes the cap, so a failed fetch can be reported as "too large" rather than "upstream error".
        let exceeded = Rc::new(Cell::new(false));
        // Our own abort handle: the body counter fires it to stop the upstream request early.
        let abort = AbortController::new().map_err(js)?;
        // The overall upstream deadline, in milliseconds (the platform takes a 32-bit number).
        let deadline = web_sys::AbortSignal::timeout_with_u32(
            u32::try_from(cfg.upstream_timeout_secs.saturating_mul(1000)).unwrap_or(u32::MAX),
        );
        // Either one ends the request.
        let signal = any_signal(&abort.signal(), &deadline).map_err(js)?;

        let init = web_sys::RequestInit::new();
        init.set_method(method);
        // Never follow: the Access service-token headers would be re-sent to the `Location` host.
        init.set_redirect(web_sys::RequestRedirect::Manual);
        // Attach the combined signal so the fetch stops on a timeout or an over-size body.
        init.set_signal(Some(&signal));

        // Request headers: the client's minus hop-by-hop, credentials and spoofable fields, then the
        // configured upstream credentials, then the gateway's own `Via` marker.
        let headers = web_sys::Headers::new().map_err(js)?;
        // The `Connection` header lists more fields that are hop-by-hop for this request only.
        let connection = p
            .req
            .headers()
            .get("connection")
            .ok()
            .flatten()
            .unwrap_or_default();
        let named = connection_named(&connection);
        for (k, v) in header_entries(&p.req.headers()) {
            // Keep a client header only if the shared policy does not drop it.
            if !drop_request_header(&k.to_ascii_lowercase(), &named) {
                headers.set(&k, &v).map_err(js)?;
            }
        }
        // `set` replaces: a client cannot leave its own copy of an upstream credential in place.
        for h in &cfg.upstream_auth_headers {
            headers.set(&h.name, &h.value).map_err(js)?;
        }
        // Our own loop marker; the client's `Via` was dropped above.
        headers.set("via", VIA_TOKEN).map_err(js)?;
        init.set_headers(&headers);

        if has_body {
            if let Some(body) = p.req.body() {
                let mut limited = limit_body(
                    &body,
                    cfg.max_body_bytes as f64,
                    exceeded.clone(),
                    abort.clone(),
                )
                .map_err(js)?;
                // A declared length is kept, so the upstream gets a fixed-length body, not a chunked one.
                if let Some(n) = cl.and_then(|v| v.trim().parse::<u32>().ok()) {
                    limited = fixed_length(&limited, n).map_err(js)?;
                }
                init.set_body(&limited);
            }
        }

        // The configured base, then the path the client asked for (already checked safe), then the query.
        let target = format!("{}{}{}", cfg.upstream_url, p.path, search);
        let request = web_sys::Request::new_with_str_and_init(&target, &init).map_err(js)?;
        let global: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        let fetched = JsFuture::from(global.fetch_with_request(&request)).await;
        let resp: web_sys::Response = match fetched {
            Ok(r) => r.unchecked_into(),
            // The fetch failed because our own counter aborted it: say "too large".
            Err(_) if exceeded.get() => return Ok(refusal(BODY_TOO_LARGE)),
            // The deadline fired: a gateway timeout.
            Err(_) if deadline.aborted() => return Ok(refusal(UPSTREAM_TIMED_OUT)),
            // Anything else (a refused connection, a TLS error) is a plain upstream error.
            Err(_) => return Ok(refusal(UPSTREAM_ERROR)),
        };
        if exceeded.get() {
            // The upstream answered before the counter tripped (e.g. an early error status); the body
            // it saw was cut short, so report the limit rather than a response to a truncated request.
            return Ok(refusal(BODY_TOO_LARGE));
        }
        // A relay has no business redirecting; treating a 3xx as an error also covers an Access login
        // redirect after the service token expires. Nothing from the response is passed on.
        if is_redirect(resp.status()) {
            if let Some(b) = resp.body() {
                // Cancel the body so the connection is released instead of drained.
                let _ = b.cancel();
            }
            return Ok(refusal(UPSTREAM_ERROR));
        }
        from_upstream(&resp).map_err(js)
    }

    /// An unauthenticated public GET: the edge cache in front of the upstream (parity with
    /// `forwardPublic`). The query string is dropped from both the cache key and the forwarded request
    /// so `?x=<random>` can neither bust the cache nor reach the origin.
    async fn public(&self, p: ProxyRequest) -> Out {
        let ttl = self.cfg.public_cache_ttl_secs;
        // Only a GET can be cached, and a TTL of zero turns the cache off.
        if p.req.method() != "GET" || ttl == 0 {
            return self.send(&p, &p.search).await;
        }
        let url = p.req.url();
        // The cache key has no query string: a random `?x=` cannot create a fresh entry each time.
        let key = url.split(['?', '#']).next().unwrap_or("").to_string();
        let cache = worker::Cache::default();
        // A hit is returned as it is: it already carries the response policy.
        if let Ok(Some(hit)) = cache.get(key.as_str(), false).await {
            let r: web_sys::Response = hit.into();
            if let Ok(out) = copy_response(&r) {
                return out;
            }
        }
        let out = self.send(&p, "").await;
        // Only successful answers are cached, so an error is never served from the cache.
        if !(200..300).contains(&out.status) {
            return out;
        }
        let _ = out
            .headers
            .set("cache-control", &format!("public, max-age={ttl}"));
        // Tee the response: one branch to the client, one into the cache (after the response is sent).
        let init = web_sys::ResponseInit::new();
        init.set_status(out.status);
        init.set_headers(&out.headers);
        let stream = match &out.body {
            Body::Stream(s) => Some(s),
            _ => None,
        };
        let Ok(full) = web_sys::Response::new_with_opt_readable_stream_and_init(stream, &init)
        else {
            return out;
        };
        // A response body can be read once, so clone it: one copy for the client, one for the cache.
        let Ok(for_cache) = full.clone() else {
            return from_upstream(&full).unwrap_or(out);
        };
        // The cache write continues after the response is sent, without delaying it.
        self.ctx.wait_until(async move {
            if let Err(e) = worker::Cache::default()
                .put(key.as_str(), for_cache.into())
                .await
            {
                worker::console_warn!("public cache put failed: {e}");
            }
        });
        from_upstream(&full).unwrap_or_else(|_| refusal(UPSTREAM_ERROR))
    }
}

/// The upstream response with the client-facing header policy applied (hop-by-hop, cookies, CORS and
/// `content-length` removed), body untouched.
fn from_upstream(resp: &web_sys::Response) -> Result<Out, JsValue> {
    // The upstream's `Connection` header names more hop-by-hop fields.
    let conn = resp.headers().get("connection")?.unwrap_or_default();
    let named = connection_named(&conn);
    let headers = web_sys::Headers::new()?;
    for (k, v) in header_entries(&resp.headers()) {
        // Keep an upstream header only if the shared policy does not drop it.
        if !drop_response_header(&k.to_ascii_lowercase(), &named) {
            headers.append(&k, &v)?;
        }
    }
    Ok(Out {
        status: resp.status(),
        headers,
        body: resp.body().map_or(Body::Empty, Body::Stream),
    })
}

/// A cached response copied into a mutable header map (cache responses have immutable headers).
fn copy_response(resp: &web_sys::Response) -> Result<Out, JsValue> {
    let headers = web_sys::Headers::new()?;
    for (k, v) in header_entries(&resp.headers()) {
        headers.append(&k, &v)?;
    }
    Ok(Out {
        status: resp.status(),
        headers,
        body: resp.body().map_or(Body::Empty, Body::Stream),
    })
}

impl Upstream for WorkerUpstream<'_> {
    /// The request the Worker forwards: method, path, query, headers and a streamed body.
    type Request = ProxyRequest;
    /// The response the Worker sends back: status, headers and a body that may stream.
    type Response = Out;

    /// Forward a request: public ones carry no credentials, gated ones carry the configured upstream headers.
    async fn forward(&self, req: ProxyRequest, kind: ForwardKind) -> Out {
        match kind {
            ForwardKind::Public => self.public(req).await,
            ForwardKind::Gated => {
                let search = req.search.clone();
                self.send(&req, &search).await
            }
        }
    }

    /// The status the single-use logic reads to decide commit or release.
    fn status(&self, resp: &Out) -> u16 {
        resp.status
    }
}
