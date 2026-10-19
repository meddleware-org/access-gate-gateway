//! The core's gRPC-web [`Transport`] over `fetch`. Only the I/O is Worker-specific: framing, protobuf
//! parsing, retries and the decision are `nft_gate_core::{grpc, chain, decision}`.

use nft_gate_core::config::AuthHeader;
use nft_gate_core::grpc::{Transport, MAX_GRPC_MESSAGE_BYTES};
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
        init.set_signal(Some(&web_sys::AbortSignal::timeout_with_u32(self.timeout_ms)));
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
        let buf = JsFuture::from(resp.array_buffer().map_err(js)?)
            .await
            .map_err(js)?;
        let arr = js_sys::Uint8Array::new(&buf);
        if arr.length() as usize > MAX_GRPC_MESSAGE_BYTES {
            anyhow::bail!("gRPC response over {MAX_GRPC_MESSAGE_BYTES} bytes");
        }
        Ok((status, arr.to_vec()))
    }

    async fn sleep_ms(&self, ms: u64) {
        worker::Delay::from(Duration::from_millis(ms)).await;
    }

    fn now_ms(&self) -> u64 {
        js_sys::Date::now() as u64
    }
}
