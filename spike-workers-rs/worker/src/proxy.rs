//! Streaming reverse-proxy of a (possibly 100 MB) request body with a byte cap, NO buffering.
//! Mirror of `gateway-workers/src/proxy.ts` (`limitBody` + `FixedLengthStream` + `forward`). The
//! chunks stay in JS-land (we read `byteLength` and re-enqueue the same `Uint8Array`), so wasm linear
//! memory does not grow with the body.
use js_sys::{Function, Object, Reflect};
use std::cell::Cell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{AbortController, ReadableStream, TransformStream};
use worker::*;

fn err(msg: &str) -> Error {
    Error::RustError(msg.to_string())
}

fn js(e: JsValue) -> Error {
    Error::JsError(format!("{e:?}"))
}

/// `limitBody`: pass `body` through, counting bytes; past `max` call `on_exceeded` and error the stream.
fn limit_body(
    body: &ReadableStream,
    max: f64,
    exceeded: Rc<Cell<bool>>,
    abort: AbortController,
) -> std::result::Result<ReadableStream, JsValue> {
    let seen = Rc::new(Cell::new(0f64));
    let transformer = Object::new();
    let transform =
        Closure::<dyn FnMut(JsValue, JsValue)>::new(move |chunk: JsValue, controller: JsValue| {
            let len = Reflect::get(&chunk, &"byteLength".into())
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            seen.set(seen.get() + len);
            let call = |name: &str, arg: JsValue| {
                if let Ok(f) = Reflect::get(&controller, &name.into()) {
                    let _ = f.unchecked_into::<Function>().call1(&controller, &arg);
                }
            };
            if seen.get() > max {
                exceeded.set(true);
                abort.abort();
                call("error", JsValue::from_str("request body too large"));
                return;
            }
            call("enqueue", chunk);
        });
    Reflect::set(&transformer, &"transform".into(), transform.as_ref())?;
    transform.forget(); // lives as long as the stream; one tiny leak per proxied request in this spike
    let ts = TransformStream::new_with_transformer(&transformer)?;
    // The pipe rejects when the counter errors the stream; the consumer sees that through `readable`.
    let p = body.pipe_to(&ts.writable());
    wasm_bindgen_futures::spawn_local(async move {
        let _ = JsFuture::from(p).await;
    });
    Ok(ts.readable())
}

fn pipe_through_fixed(
    readable: &ReadableStream,
    len: u32,
) -> std::result::Result<ReadableStream, JsValue> {
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
    Ok(readable.pipe_through(&pair.unchecked_into()))
}

pub async fn handle(req: Request, env: Env) -> Result<Response> {
    let upstream = env.var("UPSTREAM_URL")?.to_string();
    let max: f64 = env
        .var("MAX_BODY_BYTES")
        .map(|v| v.to_string().parse().unwrap_or(1e8))
        .unwrap_or(1e8);
    let url = req.url()?;
    let path = url.path().trim_start_matches("/proxy").to_string();
    if !nft_gate_core::headers::is_safe_path(&path) {
        return Response::error("{\"error\":\"invalid path\"}", 400);
    }
    let method = req.method().to_string();
    if !["GET", "HEAD", "POST", "PUT"].contains(&method.as_str()) {
        return Response::error("{\"error\":\"method not allowed\"}", 405);
    }
    let has_body = method != "GET" && method != "HEAD";
    let cl: Option<u32> = req
        .headers()
        .get("content-length")?
        .and_then(|v| v.parse().ok());
    if let Some(n) = cl {
        if f64::from(n) > max {
            return Response::error("{\"error\":\"request body too large\"}", 413);
        }
    }
    let exceeded = Rc::new(Cell::new(false));
    let abort = AbortController::new().map_err(js)?;
    let init = web_sys::RequestInit::new();
    init.set_method(&method);
    init.set_redirect(web_sys::RequestRedirect::Manual);
    init.set_signal(Some(&abort.signal()));
    // Header policy from the shared core predicate.
    let headers = web_sys::Headers::new().map_err(js)?;
    let connection = req.headers().get("connection")?.unwrap_or_default();
    let named = nft_gate_core::headers::connection_named(&connection);
    for (k, v) in req.headers().entries() {
        if !nft_gate_core::headers::drop_request_header(&k.to_ascii_lowercase(), &named) {
            headers.set(&k, &v).map_err(js)?;
        }
    }
    headers
        .set("via", nft_gate_core::headers::VIA_TOKEN)
        .map_err(js)?;
    init.set_headers(&headers);
    if has_body {
        if let Some(body) = req.inner().body() {
            let mut limited =
                limit_body(&body, max, exceeded.clone(), abort.clone()).map_err(js)?;
            if let Some(n) = cl {
                limited = pipe_through_fixed(&limited, n).map_err(js)?;
            }
            init.set_body(&limited);
        }
    }
    let target = format!(
        "{}{}{}",
        upstream.trim_end_matches('/'),
        path,
        url.query().map(|q| format!("?{q}")).unwrap_or_default()
    );
    let request = web_sys::Request::new_with_str_and_init(&target, &init).map_err(js)?;
    let global: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let fetched = JsFuture::from(global.fetch_with_request(&request)).await;
    let resp: web_sys::Response = match fetched {
        Ok(r) => r.unchecked_into(),
        Err(_) if exceeded.get() => {
            return Response::error("{\"error\":\"request body too large\"}", 413)
        }
        Err(_) => return Response::error("{\"error\":\"upstream error\"}", 502),
    };
    if exceeded.get() {
        return Response::error("{\"error\":\"request body too large\"}", 413);
    }
    if (300..400).contains(&resp.status()) {
        return Response::error("{\"error\":\"upstream error\"}", 502);
    }
    // Pass the upstream body through untouched (zero copy), minus the policy-stripped headers.
    let out_headers = web_sys::Headers::new().map_err(js)?;
    let uh = resp.headers();
    let conn = uh.get("connection").map_err(js)?.unwrap_or_default();
    let named = nft_gate_core::headers::connection_named(&conn);
    let entries = js_sys::try_iter(&uh)
        .map_err(js)?
        .ok_or_else(|| err("headers not iterable"))?;
    for e in entries {
        let pair = js_sys::Array::from(&e.map_err(js)?);
        let (k, v) = (
            pair.get(0).as_string().unwrap_or_default(),
            pair.get(1).as_string().unwrap_or_default(),
        );
        if !nft_gate_core::headers::drop_response_header(&k.to_ascii_lowercase(), &named) {
            out_headers.append(&k, &v).map_err(js)?;
        }
    }
    let init = web_sys::ResponseInit::new();
    init.set_status(resp.status());
    init.set_headers(&out_headers);
    let out = web_sys::Response::new_with_opt_readable_stream_and_init(resp.body().as_ref(), &init)
        .map_err(js)?;
    Ok(out.into())
}
