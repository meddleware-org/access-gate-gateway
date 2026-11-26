//! Runs `tests/scenario.json` against the pure state machines. The same file is run against the real
//! SQLite Durable Object under workerd by `scripts/differential.mjs`, so the DO's SQL and the core's
//! rules cannot drift apart unnoticed.
use access_gate_gateway_core::redemption::{Commit, Lease, NonceTable, RateTable, RedemptionTable};
use std::collections::HashMap;

/// The shared scenario script: the same file the Durable Object is run against under workerd.
const SCENARIO: &str = include_str!("scenario.json");

/// Scenario matches the pure state machines.
#[test]
fn scenario_matches_the_pure_state_machines() {
    let v: serde_json::Value = serde_json::from_str(SCENARIO).unwrap();
    let mut counter = 0u32;
    for section in v["sections"].as_array().unwrap() {
        // Each section starts from empty tables, so sections cannot depend on each other.
        let (mut reds, mut nonces, mut rates) =
            (RedemptionTable::new(), NonceTable::new(), RateTable::new());
        // Values a step produces (a lease token) that a later step refers to as `$name`.
        let mut vars: HashMap<String, String> = HashMap::new();
        for (i, step) in section["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{} / step {i}", section["name"]);
            let s = |k: &str| step[k].as_str().unwrap_or_default().to_string();
            let n = |k: &str, d: u64| step[k].as_u64().unwrap_or(d);
            // A token written `$name` is looked up in the values earlier steps produced.
            let token = {
                let t = s("token");
                t.strip_prefix('$')
                    .map(|name| vars[name].clone())
                    .unwrap_or(t)
            };
            let now = n("now", 0);
            let got = match step["op"].as_str().unwrap() {
                // Each `op` is one call on the state machines; the expected result is compared with the same JSON shape the Durable Object returns.
                "issue" => {
                    serde_json::json!({ "expiresAt": nonces.issue(s("nonce"), now, n("ttl", 300), n("max", 1_000_000) as usize) })
                }
                "take" => serde_json::json!({ "ok": nonces.take_if_valid(&s("nonce"), now) }),
                "rate" => serde_json::json!({ "ok": rates.check(&s("addr"), now, n("max", 30)) }),
                "lease" => {
                    counter += 1;
                    match reds.try_lease(
                        &s("key"),
                        now,
                        n("ttl", 900),
                        n("max", 1_000_000) as usize,
                        format!("tok{counter}"),
                    ) {
                        Lease::Ok(t) => {
                            if let Some(name) = step["bind"].as_str() {
                                vars.insert(name.to_string(), t);
                            }
                            serde_json::json!({ "status": "ok" })
                        }
                        Lease::Leased => serde_json::json!({ "status": "leased" }),
                        Lease::Redeemed => serde_json::json!({ "status": "redeemed" }),
                    }
                }
                "commit" => {
                    serde_json::json!({ "result": match reds.commit(&s("key"), &token, now, n("retention", 2_592_000)) { Commit::Ok => "ok", Commit::Lost => "lost" } })
                }
                "release" => {
                    reds.release(&s("key"), &token);
                    serde_json::Value::Null
                }
                other => panic!("unknown op {other}"),
            };
            if step.get("expect").is_some() {
                assert_eq!(got, step["expect"], "{at}");
            }
        }
    }
}
