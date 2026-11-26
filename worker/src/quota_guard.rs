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

/// A variable from the environment.
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
/// The analytics endpoint.
#[cfg(not(feature = "test-hooks"))]
fn endpoint(_env: &Env) -> String {
    GRAPHQL_URL.to_string()
}

/// The scheduled quota guard: when it is enabled and configured, read the account's usage and log a warning when it nears the plan's allowances. It only logs: it changes no verdict.
pub async fn run(env: &Env) {
    // Lenient like the TypeScript guard: `true` in any case enables it.
    // Off unless `QUOTA_GUARD_ENABLED` is `true`.
    if !var(env, "QUOTA_GUARD_ENABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return;
    }
    let plan = match parse_workers_plan(var(env, "WORKERS_PLAN").as_deref()) {
        Ok(p) => p,
        // A bad plan name skips the check and says so, rather than guessing which allowances apply.
        Err(e) => return console_warn!("quota-guard: {e}; skipping"),
    };
    // Both the analytics token and the account id are required; they are secrets, so neither is ever logged.
    let (Some(token), Some(account)) = (var(env, "CF_ANALYTICS_TOKEN"), var(env, "CF_ACCOUNT_ID"))
    else {
        // Only the variable names are logged, never their values.
        return console_warn!("quota-guard: CF_ANALYTICS_TOKEN / CF_ACCOUNT_ID not set; skipping");
    };
    // The window is measured from the start of the plan's day or month up to now.
    let now = js_sys::Date::now() as u64;
    let usage =
        match fetch_usage(&endpoint(env), &token, &account, window_start_ms(plan, now)).await {
            Ok(u) => u,
            // A failed query is logged and the guard does nothing: it never blocks a request.
            Err(e) => return console_warn!("quota-guard: usage query failed: {e}"),
        };
    // Compare usage with the plan's allowances (pure logic in the core).
    let a = assess_usage(&usage, plan);
    if a.warn {
        console_warn!("{}", warning_line(&a));
    }
}

/// Ask the analytics API for the usage in the window.
async fn fetch_usage(
    url: &str,
    token: &str,
    account: &str,
    since_ms: u64,
) -> Result<access_gate_gateway_core::quota::Usage, String> {
    let js = |e: JsValue| e.as_string().unwrap_or_else(|| format!("{e:?}"));
    let headers = web_sys::Headers::new().map_err(js)?;
    headers
        // The token goes in a header, never in the URL, so it cannot appear in a log of the request line.
        .set("authorization", &format!("Bearer {token}"))
        .map_err(js)?;
    headers
        .set("content-type", "application/json")
        .map_err(js)?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);
    init.set_body(&JsValue::from_str(&graphql_request_body(account, since_ms)));
    // A slow analytics API must not hold the scheduled run open.
    init.set_signal(Some(&web_sys::AbortSignal::timeout_with_u32(15_000)));
    let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(js)?;
    let global: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let resp: web_sys::Response = JsFuture::from(global.fetch_with_request(&req))
        .await
        .map_err(js)?
        .unchecked_into();
    if !resp.ok() {
        // Only the status is reported, not the response body.
        return Err(format!("graphql http {}", resp.status()));
    }
    let text = JsFuture::from(resp.text().map_err(js)?)
        .await
        .map_err(js)?
        .as_string()
        .unwrap_or_default();
    // The core parser treats a malformed or errored body as a failure, never as zero usage.
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    usage_from_graphql(&json).map_err(|e| e.to_string())
}
