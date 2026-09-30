//! `std:key-custody`: whether a content key's private bytes are in the payload.
//! This does not change the VEK.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::errors::{fail_msg, CkvfError};
use crate::types::Extension;

pub const KEY_CUSTODY_EXTENSION_ID: &str = "std:key-custody";

pub fn validate_key_custody_data(data: &Value, critical: bool) -> Result<(), CkvfError> {
    let o = data
        .as_object()
        .ok_or_else(|| CkvfError::msg("ERR_EXTENSION", "key custody data"))?;
    for key in o.keys() {
        if key != "absolute_key_id" && key != "custody" && key != "provider" && key != "key_ref" {
            return fail_msg("ERR_EXTENSION", format!("key custody field {key}"));
        }
    }
    let id = o
        .get("absolute_key_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CkvfError::msg("ERR_EXTENSION", "key custody absolute_key_id"))?;
    let _ = id;
    let custody = o
        .get("custody")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_EXTENSION", "key custody value"))?;
    if custody != "portable" && custody != "device-bound" && custody != "external" {
        return fail_msg("ERR_EXTENSION", "key custody value");
    }
    let non_exportable = custody == "device-bound" || custody == "external";
    if critical != non_exportable {
        return fail_msg("ERR_EXTENSION", "key custody critical flag");
    }
    if non_exportable {
        let refer = o.get("key_ref").and_then(|v| v.as_str()).unwrap_or("");
        if refer.is_empty() {
            return fail_msg("ERR_EXTENSION", "key custody key_ref");
        }
    }
    Ok(())
}

pub fn is_understood_critical_extension(extension: &Extension) -> bool {
    extension.id == KEY_CUSTODY_EXTENSION_ID
}

pub fn non_exportable_key_ids(critical_extensions: &[Extension]) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for extension in critical_extensions {
        if extension.id != KEY_CUSTODY_EXTENSION_ID {
            continue;
        }
        let Some(o) = extension.data.as_object() else {
            continue;
        };
        let custody = o.get("custody").and_then(|v| v.as_str()).unwrap_or("");
        if custody == "device-bound" || custody == "external" {
            if let Some(id) = o.get("absolute_key_id").and_then(|v| v.as_str()) {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

pub fn assert_custody_bindings(payload: &Map<String, Value>) -> Result<(), CkvfError> {
    let mut by_id: BTreeSet<String> = BTreeSet::new();
    let mut private_present: BTreeSet<String> = BTreeSet::new();
    if let Some(keys) = payload.get("keys").and_then(|v| v.as_array()) {
        for raw in keys {
            let Some(key) = raw.as_object() else { continue };
            let Some(id) = key.get("absolute_key_id").and_then(|v| v.as_str()) else {
                continue;
            };
            by_id.insert(id.to_string());
            if key.get("private_key").map(|v| !v.is_null()).unwrap_or(false) {
                private_present.insert(id.to_string());
            }
        }
    }
    let check = |raw: Option<&Value>| -> Result<(), CkvfError> {
        let Some(list) = raw.and_then(|v| v.as_array()) else {
            return Ok(());
        };
        for entry in list {
            let Some(ext) = entry.as_object() else { continue };
            if ext.get("id").and_then(|v| v.as_str()) != Some(KEY_CUSTODY_EXTENSION_ID) {
                continue;
            }
            let Some(data) = ext.get("data").and_then(|v| v.as_object()) else {
                continue;
            };
            let Some(id) = data.get("absolute_key_id").and_then(|v| v.as_str()) else {
                continue;
            };
            if !by_id.contains(id) {
                return fail_msg("ERR_EXTENSION", "key custody key missing");
            }
            let custody = data.get("custody").and_then(|v| v.as_str()).unwrap_or("");
            if (custody == "device-bound" || custody == "external") && private_present.contains(id) {
                return fail_msg("ERR_EXTENSION", "non-exportable key has private bytes");
            }
        }
        Ok(())
    };
    check(payload.get("extensions"))?;
    check(payload.get("critical_extensions"))?;
    Ok(())
}
