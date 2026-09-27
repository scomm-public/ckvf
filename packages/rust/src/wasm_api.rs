//! WASM build of the same CKVF crate. JSON in, JSON out.
//!
//! An unlocked vault is `{ "container", "payload", "vek" }` with `vek` as
//! unpadded base64url. Callers keep that object in memory the same way the
//! native API keeps `UnlockedVault`.

use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

use crate::types::{UnlockedVault, VaultContainer, VaultPayload};
use crate::vault::serialize_container;

fn err(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

fn unlocked_json(unlocked: &UnlockedVault) -> Result<String, JsValue> {
    let body = json!({
        "container": unlocked.container.to_json(),
        "payload": unlocked.payload.to_json(),
        "vek": crate::base64url_encode(&unlocked.vek),
    });
    serde_json::to_string(&body).map_err(|e| err(e.to_string()))
}

fn unlocked_from_json(text: &str) -> Result<UnlockedVault, JsValue> {
    let v: Value = serde_json::from_str(text).map_err(|e| err(e.to_string()))?;
    let container = v
        .get("container")
        .and_then(VaultContainer::from_json)
        .ok_or_else(|| JsValue::from_str("ERR_FORMAT: container"))?;
    let payload = v
        .get("payload")
        .and_then(VaultPayload::from_json)
        .ok_or_else(|| JsValue::from_str("ERR_FORMAT: payload"))?;
    let vek = v
        .get("vek")
        .and_then(|x| x.as_str())
        .ok_or_else(|| JsValue::from_str("ERR_FORMAT: vek"))?;
    let vek = crate::base64url_decode(vek).map_err(|e| err(&e.0))?;
    Ok(UnlockedVault {
        container,
        payload,
        vek,
    })
}

#[wasm_bindgen]
pub fn jcs(json_text: &str) -> Result<String, JsValue> {
    crate::canonicalize_json(json_text).map_err(|e| err(&e.0))
}

#[wasm_bindgen]
pub fn base64url_encode(bytes: &[u8]) -> String {
    crate::base64url_encode(bytes)
}

#[wasm_bindgen]
pub fn base64url_decode(text: &str) -> Result<Vec<u8>, JsValue> {
    crate::base64url_decode(text).map_err(|e| err(&e.0))
}

#[wasm_bindgen]
pub fn can_read_version(version: &str) -> bool {
    crate::can_read_version(version)
}

#[wasm_bindgen]
pub fn can_write_version(version: &str) -> bool {
    crate::can_write_version(version)
}

/// `identity_id` for a raw email or DNS name (canonicalized first).
#[wasm_bindgen]
pub fn identity_id(identity_type: &str, value: &str) -> Result<String, JsValue> {
    let identity = crate::make_identity(identity_type, value).map_err(|e| err(e.to_string()))?;
    Ok(identity.identity_id)
}

/// Create a password-wrapped vault. Returns the unlocked JSON envelope.
#[wasm_bindgen]
pub fn create_vault(
    identity_type: &str,
    identity_value: &str,
    password: &str,
    now: Option<String>,
) -> Result<String, JsValue> {
    let unlocked = crate::create(identity_type, identity_value, password, now.as_deref())
        .map_err(|e| err(e.to_string()))?;
    unlocked_json(&unlocked)
}

/// Open a container JSON document with a password.
#[wasm_bindgen]
pub fn open_vault(container_json: &str, password: &str) -> Result<String, JsValue> {
    let unlocked = crate::decrypt(container_json, password).map_err(|e| err(e.to_string()))?;
    unlocked_json(&unlocked)
}

/// Lock an unlocked JSON envelope. Returns canonical container JSON.
#[wasm_bindgen]
pub fn lock_vault(unlocked_json: &str) -> Result<String, JsValue> {
    let unlocked = unlocked_from_json(unlocked_json)?;
    let container = crate::encrypt(&unlocked).map_err(|e| err(e.to_string()))?;
    serialize_container(&container).map_err(|e| err(e.to_string()))
}

/// Merge two unlocked JSON envelopes.
#[wasm_bindgen]
pub fn merge_vaults(
    left_json: &str,
    right_json: &str,
    now: Option<String>,
) -> Result<String, JsValue> {
    let left = unlocked_from_json(left_json)?;
    let right = unlocked_from_json(right_json)?;
    let merged = crate::merge(&left, &right, now.as_deref()).map_err(|e| err(e.to_string()))?;
    unlocked_json(&merged)
}
