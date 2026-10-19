//! Rendering of the gateway's own JSON answers.
//!
//! The TypeScript Worker serialised `{ error, code }` and `{ nonce, expiresAt }` in that key order;
//! `serde_json::Value` objects are sorted alphabetically, so the body is rendered by hand to keep the
//! bytes identical (clients parse JSON, but a byte-for-byte match keeps the differential check strict).

use serde_json::Value;

/// Keys in the order the TypeScript Worker wrote them; any other key follows, sorted.
const KEY_ORDER: [&str; 4] = ["error", "code", "nonce", "expiresAt"];

/// `value` as compact JSON, with an object's keys in [`KEY_ORDER`] first.
pub fn render(value: &Value) -> String {
    let Value::Object(map) = value else {
        return value.to_string();
    };
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| {
        let rank = |k: &String| {
            KEY_ORDER
                .iter()
                .position(|o| *o == k)
                .unwrap_or(KEY_ORDER.len())
        };
        rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
    });
    let mut out = String::from("{");
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&Value::String((*k).clone()).to_string());
        out.push(':');
        if let Some(v) = map.get(*k) {
            out.push_str(&v.to_string());
        }
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_keep_the_typescript_order() {
        assert_eq!(
            render(&json!({"code": "leased", "error": "busy"})),
            r#"{"error":"busy","code":"leased"}"#
        );
        assert_eq!(
            render(&json!({"expiresAt": 5, "nonce": "eu.ab"})),
            r#"{"nonce":"eu.ab","expiresAt":5}"#
        );
        assert_eq!(render(&json!({"error": "x"})), r#"{"error":"x"}"#);
    }

    #[test]
    fn unknown_keys_follow_sorted_and_strings_are_escaped() {
        assert_eq!(
            render(&json!({"z": 1, "a": "q\"uote", "error": "e"})),
            r#"{"error":"e","a":"q\"uote","z":1}"#
        );
        assert_eq!(render(&json!([1, 2])), "[1,2]");
        assert_eq!(render(&json!({})), "{}");
    }
}
