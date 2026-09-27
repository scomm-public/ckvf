//! RFC 8785 JSON Canonicalization Scheme.
//!
//! Object keys sort by UTF-16 code units. Integer-valued finite numbers render
//! without a fraction. This matches the codec the Dart CKVF package applied
//! to protocol payloads.

use serde_json::Value;

#[derive(Debug)]
pub struct JcsError(pub String);

pub fn canonicalize_json(input: &str) -> Result<String, JcsError> {
    let value: Value = serde_json::from_str(input).map_err(|e| JcsError(e.to_string()))?;
    canonicalize(&value)
}

/// Canonicalize an already-parsed JSON value (RFC 8785).
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    serialize(value, 0)
}

/// UTF-8 bytes of the JCS form of `value`.
pub fn canonicalize_bytes(value: &Value) -> Result<Vec<u8>, JcsError> {
    Ok(canonicalize(value)?.into_bytes())
}

fn serialize(value: &Value, depth: usize) -> Result<String, JcsError> {
    if depth > 64 {
        return Err(JcsError("JCS nesting".into()));
    }
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(true) => Ok("true".into()),
        Value::Bool(false) => Ok("false".into()),
        Value::Number(n) => format_number(n),
        Value::String(s) => serde_json::to_string(s).map_err(|e| JcsError(e.to_string())),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                parts.push(serialize(item, depth + 1)?);
            }
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let encoded_key = serde_json::to_string(key).map_err(|e| JcsError(e.to_string()))?;
                let encoded_value = serialize(&map[key], depth + 1)?;
                parts.push(format!("{encoded_key}:{encoded_value}"));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

fn format_number(n: &serde_json::Number) -> Result<String, JcsError> {
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    let Some(f) = n.as_f64() else {
        return Err(JcsError("non-finite number".into()));
    };
    if !f.is_finite() {
        return Err(JcsError("non-finite number".into()));
    }
    if f == 0.0 {
        return Ok("0".into());
    }
    if f.fract() == 0.0 && f.abs() < (1u64 << 53) as f64 {
        return Ok((f as i64).to_string());
    }
    serde_json::to_string(&f).map_err(|e| JcsError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::canonicalize_json;

    #[test]
    fn sorts_object_keys() {
        let out = canonicalize_json(r#"{"b":1,"a":2}"#).unwrap();
        assert_eq!(out, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn integer_valued_float_has_no_fraction() {
        let out = canonicalize_json("1.0").unwrap();
        assert_eq!(out, "1");
    }

    #[test]
    fn array_and_string() {
        let out = canonicalize_json(r#"[1,"x",true,null]"#).unwrap();
        assert_eq!(out, r#"[1,"x",true,null]"#);
    }
}
