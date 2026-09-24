//! Canonical JSON and the bundle checksum.
//!
//! The checksum covers a canonical encoding (object keys sorted, no
//! insignificant whitespace) of the bundle without its checksum field, so it
//! does not depend on how the file is pretty-printed or on serde_json's map
//! ordering features.

use aienos_kernel::crypto::sha256;
use serde_json::Value;

pub const CHECKSUM_FIELD: &str = "bundle_checksum_sha256";

pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*key).clone()).to_string());
                out.push(':');
                write(&map[*key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of the canonical bundle with the checksum field removed.
pub fn checksum(bundle: &Value) -> String {
    let mut body = bundle.clone();
    if let Value::Object(map) = &mut body {
        map.remove(CHECKSUM_FIELD);
    }
    hex(&sha256::hash(canonical(&body).as_bytes()))
}

/// Returns the bundle with a fresh checksum field.
pub fn seal(mut bundle: Value) -> Value {
    let sum = checksum(&bundle);
    if let Value::Object(map) = &mut bundle {
        map.insert(CHECKSUM_FIELD.into(), Value::String(sum));
    }
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_and_whitespace_do_not_change_the_checksum() {
        let a: Value = serde_json::from_str(r#"{"b": 1, "a": {"y": [1, 2], "x": "s"}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":"s","y":[1,2]},"b":1}"#).unwrap();
        assert_eq!(canonical(&a), r#"{"a":{"x":"s","y":[1,2]},"b":1}"#);
        assert_eq!(checksum(&a), checksum(&b));
    }

    #[test]
    fn sealed_bundle_verifies_and_any_edit_breaks_it() {
        let sealed = seal(json!({"schema_version": "3.0.0", "value": 7}));
        let stored = sealed[CHECKSUM_FIELD].as_str().unwrap().to_string();
        assert_eq!(stored, checksum(&sealed));
        let mut edited = sealed.clone();
        edited["value"] = json!(8);
        assert_ne!(stored, checksum(&edited));
    }
}
