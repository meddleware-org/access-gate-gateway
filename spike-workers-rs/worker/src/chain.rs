//! Item 5: the SHARED chain logic (`nft_gate_core::{grpc, chain, decision}`) running on `fetch`.
//! Only the transport is Worker-specific; framing, protobuf parsing and the decision are core.
use nft_gate_core::chain::SuiRpc;
use nft_gate_core::decision::{verify_access_request, ChainQuery, NonceTake, VerifyParams};
use nft_gate_core::grpc::{Transport, MAX_GRPC_MESSAGE_BYTES};
use std::time::Duration;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use worker::*;

pub struct WorkerTransport {
    /// Optional `SUI_RPC_AUTH_HEADER` (`Name: value`).
    auth: Option<(String, String)>,
    timeout_ms: u32,
}

impl Transport for WorkerTransport {
    async fn post_grpc_web(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(Option<String>, Vec<u8>)> {
        let to_err = |e: wasm_bindgen::JsValue| anyhow::anyhow!("{e:?}");
        let headers = web_sys::Headers::new().map_err(to_err)?;
        headers
            .set("content-type", "application/grpc-web+proto")
            .map_err(to_err)?;
        headers
            .set("accept", "application/grpc-web+proto")
            .map_err(to_err)?;
        if let Some((k, v)) = &self.auth {
            headers.set(k, v).map_err(to_err)?;
        }
        let init = web_sys::RequestInit::new();
        init.set_method("POST");
        init.set_headers(&headers);
        let bytes = js_sys::Uint8Array::from(body.as_slice());
        init.set_body(&bytes);
        init.set_signal(Some(&web_sys::AbortSignal::timeout_with_u32(
            self.timeout_ms,
        )));
        let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(to_err)?;
        let global: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
        let resp: web_sys::Response = JsFuture::from(global.fetch_with_request(&req))
            .await
            .map_err(to_err)?
            .unchecked_into();
        if !resp.ok() {
            anyhow::bail!("gRPC-web HTTP {}", resp.status());
        }
        let status = resp.headers().get("grpc-status").map_err(to_err)?;
        let buf = JsFuture::from(resp.array_buffer().map_err(to_err)?)
            .await
            .map_err(to_err)?;
        let arr = js_sys::Uint8Array::new(&buf);
        if arr.length() as usize > MAX_GRPC_MESSAGE_BYTES {
            anyhow::bail!("gRPC response over {MAX_GRPC_MESSAGE_BYTES} bytes");
        }
        Ok((status, arr.to_vec()))
    }

    async fn sleep_ms(&self, ms: u64) {
        Delay::from(Duration::from_millis(ms)).await;
    }

    fn now_ms(&self) -> u64 {
        js_sys::Date::now() as u64
    }
}

fn rpc(env: &Env) -> Result<SuiRpc<WorkerTransport>> {
    let url = env.var("SUI_RPC_URL")?.to_string();
    Ok(SuiRpc::new(
        WorkerTransport {
            auth: None,
            timeout_ms: 15_000,
        },
        url,
        0,
        15_000,
    ))
}

fn json(v: serde_json::Value) -> Result<Response> {
    Response::from_json(&v)
}

pub async fn handle(req: Request, env: Env) -> Result<Response> {
    let url = req.url()?;
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let get = |k: &str| q.get(k).cloned().unwrap_or_default();
    let rpc = rpc(&env)?;
    match url.path() {
        "/chain/tx" => {
            let r = rpc
                .consume_tx_valid(
                    &get("digest"),
                    &get("sender"),
                    &get("event"),
                    q.get("gate").map(String::as_str),
                    10_u64.pow(9),
                )
                .await;
            match r {
                Ok(ok) => json(serde_json::json!({ "consumeValid": ok })),
                Err(e) => Ok(
                    Response::from_json(&serde_json::json!({ "error": e.to_string() }))?
                        .with_status(502),
                ),
            }
        }
        "/chain/gate" => match rpc.gate_access_blocked(&get("gate")).await {
            Ok(b) => json(serde_json::json!({ "blocked": b })),
            Err(e) => Ok(
                Response::from_json(&serde_json::json!({ "error": e.to_string() }))?
                    .with_status(502),
            ),
        },
        "/chain/owned" => match rpc
            .owns_nft(
                &get("address"),
                &get("type"),
                q.get("gate").map(String::as_str),
            )
            .await
        {
            Ok(b) => json(serde_json::json!({ "owns": b })),
            Err(e) => Ok(
                Response::from_json(&serde_json::json!({ "error": e.to_string() }))?
                    .with_status(502),
            ),
        },
        _ => Response::error("not found", 404),
    }
}

/// Nonce consumption through the DO shard (`take`), as `verify_access_request` expects.
struct DoNonces {
    stub: Stub,
}

impl NonceTake for DoNonces {
    async fn take_if_valid(&self, nonce: &str) -> anyhow::Result<bool> {
        let mut u = Url::parse("https://do.internal/take").map_err(|e| anyhow::anyhow!("{e}"))?;
        u.query_pairs_mut().append_pair("nonce", nonce);
        let mut resp = self
            .stub
            .fetch_with_str(u.as_str())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let v: serde_json::Value = resp.json().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(v["ok"].as_bool().unwrap_or(false))
    }
}

pub async fn verify(req: Request, env: Env) -> Result<Response> {
    let token = req
        .headers()
        .get("authorization")?
        .and_then(|a| a.strip_prefix("Bearer ").map(str::to_string))
        .unwrap_or_default();
    let var = |k: &str| env.var(k).map(|v| v.to_string());
    let params = VerifyParams {
        single_use: var("SINGLE_USE")? == "true",
        gateway_origin: var("GATEWAY_ORIGIN")?,
        gate_id: var("GATE_ID")?,
        network: var("NETWORK")?,
        nft_type: var("NFT_TYPE")?,
        consume_max_age_secs: 432_000,
    };
    let stub = env
        .durable_object("NONCE_STATE")?
        .id_from_name("nonce:g")?
        .get_stub()?;
    let rpc = rpc(&env)?;
    match verify_access_request(&params, &DoNonces { stub }, &token, &rpc).await {
        Ok(v) => json(
            serde_json::json!({ "allowed": true, "address": v.address, "redemptionKey": v.redemption_key }),
        ),
        Err(d) => {
            let status = if matches!(d, nft_gate_core::decision::Denied::ChainError) {
                502
            } else {
                403
            };
            Ok(Response::from_json(&serde_json::json!({ "allowed": false, "denied": format!("{d:?}"), "error": d.reason() }))?.with_status(status))
        }
    }
}
