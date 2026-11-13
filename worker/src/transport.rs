//! The core's gRPC-web [`Transport`] over `fetch`. Only the I/O is Worker-specific: framing, protobuf
//! parsing, retries and the decision are `access_gate_gateway_core::{grpc, chain, decision}`.

use access_gate_gateway_core::config::AuthHeader;
use access_gate_gateway_core::grpc::{Transport, MAX_GRPC_MESSAGE_BYTES};
use std::time::Duration;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

pub struct WorkerTransport {
    /// `SUI_RPC_AUTH_HEADER`, sent with every call.
    pub auth: Option<AuthHeader>,
    /// Per-call deadline (`RPC_TIMEOUT_SECS`).
    pub timeout_ms: u32,
}

fn js(e: JsValue) -> anyhow::Error {
    anyhow::anyhow!("{}", e.as_string().unwrap_or_else(|| format!("{e:?}")))
}

impl Transport for WorkerTransport {
    async fn post_grpc_web(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(Option<String>, Vec<u8>)> {
        let headers = web_sys::Headers::new().map_err(js)?;
        headers
            .set("content-type", "application/grpc-web+proto")
            .map_err(js)?;
        headers
            .set("accept", "application/grpc-web+proto")
            .map_err(js)?;
        if let Some(h) = &self.auth {
            headers.set(&h.name, &h.value).map_err(js)?;
        }
        let init = web_sys::RequestInit::new();
        init.set_method("POST");
        init.set_headers(&headers);
        init.set_body(&js_sys::Uint8Array::from(body.as_slice()));
        // The fetch is aborted by the timeout OR by this controller, which the body read triggers when the response is over the size limit:
        // cancelling the reader alone leaves the connection open (workerd drains it), so the request would only end at the timeout.
        let controller = web_sys::AbortController::new().map_err(js)?;
        let timeout = web_sys::AbortSignal::timeout_with_u32(self.timeout_ms);
        let signals = js_sys::Array::of2(&timeout, &controller.signal());
        let signal_ctor =
            js_sys::Reflect::get(&js_sys::global(), &"AbortSignal".into()).map_err(js)?;
        let any = js_sys::Reflect::get(&signal_ctor, &"any".into()).map_err(js)?;
        let either: web_sys::AbortSignal = any
            .unchecked_ref::<js_sys::Function>()
            .call1(&signal_ctor, &signals)
            .map_err(js)?
            .unchecked_into();
        init.set_signal(Some(&either));
        let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(js)?;
        let global: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        let resp: web_sys::Response = JsFuture::from(global.fetch_with_request(&req))
            .await
            .map_err(js)?
            .unchecked_into();
        if !resp.ok() {
            anyhow::bail!("gRPC-web HTTP {}", resp.status());
        }
        let status = resp.headers().get("grpc-status").map_err(js)?;
        // Bound the body while it is read, not after: a faulty or hostile fullnode must not make the isolate buffer far more than the
        // limit (the content-length check alone misses chunked bodies). Over the limit, the stream is cancelled and the call fails.
        if let Some(len) = resp.headers().get("content-length").map_err(js)? {
            if len
                .parse::<usize>()
                .is_ok_and(|n| n > MAX_GRPC_MESSAGE_BYTES)
            {
                anyhow::bail!("gRPC response over {MAX_GRPC_MESSAGE_BYTES} bytes");
            }
        }
        let body = resp
            .body()
            .ok_or_else(|| anyhow::anyhow!("gRPC response has no body"))?;
        let reader: web_sys::ReadableStreamDefaultReader = body.get_reader().unchecked_into();
        let mut out: Vec<u8> = Vec::new();
        loop {
            let chunk = JsFuture::from(reader.read()).await.map_err(js)?;
            let done = js_sys::Reflect::get(&chunk, &"done".into())
                .map_err(js)?
                .as_bool()
                .unwrap_or(true);
            if done {
                break;
            }
            let value = js_sys::Reflect::get(&chunk, &"value".into()).map_err(js)?;
            let part: js_sys::Uint8Array = value.unchecked_into();
            if out.len() + part.length() as usize > MAX_GRPC_MESSAGE_BYTES {
                controller.abort();
                anyhow::bail!("gRPC response over {MAX_GRPC_MESSAGE_BYTES} bytes");
            }
            out.extend_from_slice(&part.to_vec());
        }
        Ok((status, out))
    }

    async fn sleep_ms(&self, ms: u64) {
        worker::Delay::from(Duration::from_millis(ms)).await;
    }

    fn now_ms(&self) -> u64 {
        js_sys::Date::now() as u64
    }
}
