//! The optional quota guard (`scheduled` handler; off unless `QUOTA_GUARD_ENABLED=true` plus a cron
//! trigger). The logic is `access_gate_gateway_core::quota`; this file only does the HTTP call and the log line.
//! It warns near an allowance and never rejects: every error is logged and swallowed.

use access_gate_gateway_core::quota::{
    assess_usage, graphql_request_body, parse_workers_plan, usage_from_graphql, warning_line,
    window_start_ms, GRAPHQL_URL,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{console_warn, Env};

fn var(env: &Env, key: &str) -> Option<String> {
    js_sys::Reflect::get(env, &JsValue::from_str(key))
        .ok()
        .and_then(|v| v.as_string())
}

/// Where the Analytics query goes. The production build always uses Cloudflare's endpoint; only the
/// test-hooks build lets the suite point it at a stub.
#[cfg(feature = "test-hooks")]
fn endpoint(env: &Env) -> String {
    var(env, "QUOTA_GRAPHQL_URL").unwrap_or_else(|| GRAPHQL_URL.to_string())
}
#[cfg(not(feature = "test-hooks"))]
fn endpoint(_env: &Env) -> String {
    GRAPHQL_URL.to_string()
}

pub async fn run(env: &Env) {
    // Lenient like the TypeScript guard: `true` in any case enables it.
    if !var(env, "QUOTA_GUARD_ENABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return;
    }
    let plan = match parse_workers_plan(var(env, "WORKERS_PLAN").as_deref()) {
        Ok(p) => p,
        Err(e) => return console_warn!("quota-guard: {e}; skipping"),
    };
    let (Some(token), Some(account)) = (var(env, "CF_ANALYTICS_TOKEN"), var(env, "CF_ACCOUNT_ID"))
    else {
        return console_warn!("quota-guard: CF_ANALYTICS_TOKEN / CF_ACCOUNT_ID not set; skipping");
    };
    let now = js_sys::Date::now() as u64;
    let usage =
        match fetch_usage(&endpoint(env), &token, &account, window_start_ms(plan, now)).await {
            Ok(u) => u,
            Err(e) => return console_warn!("quota-guard: usage query failed: {e}"),
        };
    let a = assess_usage(&usage, plan);
    if a.warn {
        console_warn!("{}", warning_line(&a));
    }
}

async fn fetch_usage(
    url: &str,
    token: &str,
    account: &str,
    since_ms: u64,
) -> Result<access_gate_gateway_core::quota::Usage, String> {
    let js = |e: JsValue| e.as_string().unwrap_or_else(|| format!("{e:?}"));
    let headers = web_sys::Headers::new().map_err(js)?;
    headers
        .set("authorization", &format!("Bearer {token}"))
        .map_err(js)?;
    headers
        .set("content-type", "application/json")
        .map_err(js)?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(&graphql_request_body(account, since_ms)));
    init.set_signal(Some(&web_sys::AbortSignal::timeout_with_u32(15_000)));
    let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(js)?;
    let global: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let resp: web_sys::Response = JsFuture::from(global.fetch_with_request(&req))
        .await
        .map_err(js)?
        .unchecked_into();
    if !resp.ok() {
        return Err(format!("graphql http {}", resp.status()));
    }
    let text = JsFuture::from(resp.text().map_err(js)?)
        .await
        .map_err(js)?
        .as_string()
        .unwrap_or_default();
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    usage_from_graphql(&json).map_err(|e| e.to_string())
}
