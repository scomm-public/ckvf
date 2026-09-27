//! Container and payload shape validation (fail-closed).

use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;

use crate::b64;
use crate::errors::{fail, fail_msg, CkvfError};
use crate::limits::{ParserLimits, DEFAULT_LIMITS, PEPPER_MIN_ARGON2ID};
use crate::registries::{
    is_forbidden_family, ALGORITHM_SUITES, KEY_ENCODINGS, KEY_FAMILIES, KEY_PURPOSES, KEY_STATUSES,
    PEPPER_UNLOCK_METHODS, UNLOCK_METHODS,
};
use crate::types::{
    Extension, KeyRecord, UnlockSlot, VaultContainer, VaultPayload, CKVF_FORMAT,
};
use crate::version::can_read_version;

// Helper wrappers so we don't need to export contains helpers from registries.
fn algorithm_suites_contains(s: &str) -> bool {
    ALGORITHM_SUITES.contains(&s)
}
fn key_encodings_contains(s: &str) -> bool {
    KEY_ENCODINGS.contains(&s)
}
fn key_families_contains(s: &str) -> bool {
    KEY_FAMILIES.contains(&s)
}
fn key_purposes_contains(s: &str) -> bool {
    KEY_PURPOSES.contains(&s)
}
fn key_statuses_contains(s: &str) -> bool {
    KEY_STATUSES.contains(&s)
}
fn pepper_unlock_methods_contains(s: &str) -> bool {
    PEPPER_UNLOCK_METHODS.contains(&s)
}
fn unlock_methods_contains(s: &str) -> bool {
    UNLOCK_METHODS.contains(&s)
}

pub fn parse_json_limited(text: &str, limits: ParserLimits) -> Result<Value, CkvfError> {
    if text.len() > limits.max_vault_bytes {
        return fail_msg("ERR_PARSER_LIMIT", "vault JSON too large");
    }
    let parsed: Value =
        serde_json::from_str(text).map_err(|_| CkvfError::msg("ERR_JSON", "invalid JSON"))?;
    assert_nesting(&parsed, 0, limits.max_json_nesting)?;
    Ok(parsed)
}

fn assert_nesting(value: &Value, depth: usize, max: usize) -> Result<(), CkvfError> {
    if depth > max {
        return fail_msg("ERR_PARSER_LIMIT", "JSON nesting");
    }
    match value {
        Value::Array(items) => {
            for v in items {
                assert_nesting(v, depth + 1, max)?;
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                assert_nesting(v, depth + 1, max)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn reject_unknown_keys(obj: &serde_json::Map<String, Value>, allowed: &[&str]) -> Result<(), CkvfError> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            return fail_msg("ERR_FORMAT", format!("unknown field {k}"));
        }
    }
    Ok(())
}

fn as_object<'a>(raw: &'a Value, err: &str) -> Result<&'a serde_json::Map<String, Value>, CkvfError> {
    raw.as_object()
        .ok_or_else(|| CkvfError::msg("ERR_JSON", err.to_string()))
}

pub fn validate_container_shape(
    raw: &Value,
    limits: ParserLimits,
) -> Result<VaultContainer, CkvfError> {
    let o = as_object(raw, "container is not an object")?;
    reject_unknown_keys(
        o,
        &[
            "format",
            "version",
            "vault_id",
            "generation",
            "previous_generation_hash",
            "generation_hash",
            "crypto",
            "unlock_slots",
            "ciphertext",
            "tag",
            "extensions",
            "critical_extensions",
        ],
    )?;
    if o.get("format").and_then(|v| v.as_str()) != Some(CKVF_FORMAT) {
        return fail_msg("ERR_FORMAT", "format must be CKVF");
    }
    let version = o
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_VERSION", "unsupported version"))?;
    if !can_read_version(version) {
        return fail_msg("ERR_VERSION", format!("unsupported version {version}"));
    }
    let vault_id = o
        .get("vault_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "vault_id"))?;
    decode_b64_len(vault_id, Some(16))?;
    let generation = o
        .get("generation")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "generation"))?;
    if generation < 1 {
        return fail_msg("ERR_FORMAT", "generation");
    }
    if generation == 1 {
        if !matches!(o.get("previous_generation_hash"), Some(Value::Null) | None) {
            return fail_msg(
                "ERR_FORMAT",
                "generation 1 previous_generation_hash must be null",
            );
        }
    } else {
        let prev = o
            .get("previous_generation_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "previous_generation_hash"))?;
        decode_b64_len(prev, Some(32))?;
    }
    let gen_hash = o
        .get("generation_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "generation_hash"))?;
    decode_b64_len(gen_hash, Some(32))?;
    let crypto = as_object(
        o.get("crypto")
            .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "crypto"))?,
        "crypto",
    )?;
    reject_unknown_keys(crypto, &["aead", "iv"])?;
    if crypto.get("aead").and_then(|v| v.as_str()) != Some("A256GCM") {
        return fail_msg("ERR_NOT_IMPLEMENTED", "only A256GCM is mandatory in v1.0");
    }
    let iv = crypto
        .get("iv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "iv"))?;
    decode_b64_len(iv, Some(12))?;
    let raw_slots = o
        .get("unlock_slots")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "unlock_slots"))?;
    if raw_slots.len() > limits.max_unlock_slots {
        return fail_msg("ERR_PARSER_LIMIT", "too many unlock slots");
    }
    let mut slots = Vec::with_capacity(raw_slots.len());
    let mut ids = HashSet::new();
    for s in raw_slots {
        let slot = validate_unlock_slot(s, limits)?;
        if !ids.insert(slot.slot_id.clone()) {
            return fail_msg("ERR_SLOT_ID", "duplicate slot_id");
        }
        slots.push(slot);
    }
    let ciphertext = o
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "ciphertext"))?;
    let ct = decode_b64_len(ciphertext, None)?;
    if ct.len() > limits.max_payload_bytes {
        return fail_msg("ERR_PARSER_LIMIT", "ciphertext too large");
    }
    let tag = o
        .get("tag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "tag"))?;
    decode_b64_len(tag, Some(16))?;
    validate_extensions(
        o.get("extensions").unwrap_or(&Value::Array(vec![])),
        false,
        limits,
    )?;
    validate_extensions(
        o.get("critical_extensions")
            .unwrap_or(&Value::Array(vec![])),
        true,
        limits,
    )?;
    VaultContainer::from_json(raw).ok_or_else(|| CkvfError::msg("ERR_FORMAT", "container"))
}

pub fn validate_unlock_slot(raw: &Value, limits: ParserLimits) -> Result<UnlockSlot, CkvfError> {
    let o = as_object(raw, "unlock slot")?;
    reject_unknown_keys(
        o,
        &["slot_id", "method", "created_at", "kdf", "oprf", "wrap"],
    )?;
    let slot_id = o
        .get("slot_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_SLOT_ID", "slot_id"))?;
    decode_b64_len(slot_id, Some(16))?;
    let method = o
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_NOT_IMPLEMENTED", "unlock method"))?;
    if !unlock_methods_contains(method) {
        return fail_msg("ERR_NOT_IMPLEMENTED", format!("unlock method {method}"));
    }
    let created_at = o
        .get("created_at")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "created_at"))?;
    if !is_rfc3339_z(created_at) {
        return fail_msg("ERR_FORMAT", "created_at");
    }
    let pepper = pepper_unlock_methods_contains(method);
    if pepper {
        validate_oprf(o.get("oprf"))?;
    } else if o.contains_key("oprf") {
        return fail_msg(
            "ERR_FORMAT",
            "oprf is only allowed on *-oprf-argon2id slots",
        );
    }
    if method == "device-wrap-a256gcm" && o.contains_key("kdf") {
        return fail_msg("ERR_KDF", "device-wrap slots carry no kdf");
    }
    if method == "password-argon2id" || pepper {
        let k = as_object(
            o.get("kdf")
                .ok_or_else(|| CkvfError::msg("ERR_KDF", "missing kdf"))?,
            "kdf",
        )?;
        reject_unknown_keys(k, &["alg", "salt", "m", "t", "p", "key_length"])?;
        if k.get("alg").and_then(|v| v.as_str()) != Some("Argon2id") {
            return fail_msg("ERR_KDF", "alg");
        }
        let salt = k
            .get("salt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CkvfError::msg("ERR_KDF", "salt"))?;
        let salt_bytes = decode_b64_len(salt, None)?;
        if salt_bytes.len() < 16 {
            return fail_msg("ERR_KDF", "salt too short");
        }
        let m = k
            .get("m")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| CkvfError::new("ERR_KDF"))? as u32;
        let t = k
            .get("t")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| CkvfError::new("ERR_KDF"))? as u32;
        let p = k
            .get("p")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| CkvfError::new("ERR_KDF"))? as u32;
        if k.get("key_length").and_then(|v| v.as_u64()) != Some(32) {
            return fail_msg("ERR_KDF", "key_length");
        }
        if m < limits.min_argon2_memory_kib
            || t < limits.min_argon2_time
            || p < limits.min_argon2_parallelism
        {
            return fail_msg("ERR_KDF", "unsafe Argon2id parameters");
        }
        if m > limits.max_argon2_memory_kib
            || t > limits.max_argon2_time
            || p > limits.max_argon2_parallelism
        {
            return fail_msg("ERR_KDF", "Argon2id parameters exceed parser limits");
        }
        if pepper && (m < PEPPER_MIN_ARGON2ID.m || t < PEPPER_MIN_ARGON2ID.t) {
            return fail_msg("ERR_KDF", "pepper slots need m >= 65536 and t >= 3");
        }
    }
    let w = as_object(
        o.get("wrap")
            .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "wrap"))?,
        "wrap",
    )?;
    reject_unknown_keys(w, &["alg", "iv", "ciphertext", "tag"])?;
    if w.get("alg").and_then(|v| v.as_str()) != Some("A256GCM") {
        return fail_msg("ERR_NOT_IMPLEMENTED", "wrap alg");
    }
    let wiv = w
        .get("iv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "wrap fields"))?;
    let wct = w
        .get("ciphertext")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "wrap fields"))?;
    let wtag = w
        .get("tag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "wrap fields"))?;
    decode_b64_len(wiv, Some(12))?;
    decode_b64_len(wct, Some(32))?;
    decode_b64_len(wtag, Some(16))?;
    UnlockSlot::from_json(raw).ok_or_else(|| CkvfError::msg("ERR_FORMAT", "unlock slot"))
}

fn validate_oprf(raw: Option<&Value>) -> Result<(), CkvfError> {
    let o = as_object(
        raw.ok_or_else(|| CkvfError::msg("ERR_FORMAT", "oprf is required"))?,
        "oprf",
    )?;
    reject_unknown_keys(o, &["suite", "mode", "kid", "public_key"])?;
    if o.get("suite").and_then(|v| v.as_str()) != Some("ristretto255-SHA512") {
        return fail_msg("ERR_NOT_IMPLEMENTED", "oprf suite");
    }
    if o.get("mode").and_then(|v| v.as_str()) != Some("poprf") {
        return fail_msg("ERR_NOT_IMPLEMENTED", "oprf mode");
    }
    let kid = o
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "oprf kid"))?;
    if kid.is_empty() || kid.len() > 64 {
        return fail_msg("ERR_FORMAT", "oprf kid");
    }
    let pk = o
        .get("public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "oprf public_key"))?;
    decode_b64_len(pk, Some(32))?;
    Ok(())
}

pub fn validate_payload_shape(raw: &Value, limits: ParserLimits) -> Result<VaultPayload, CkvfError> {
    let o = as_object(raw, "payload is not an object")?;
    reject_unknown_keys(
        o,
        &[
            "identity",
            "msk",
            "keys",
            "preferred_keys",
            "metadata",
            "tombstones",
            "extensions",
            "critical_extensions",
        ],
    )?;
    let keys = o
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CkvfError::msg("ERR_PARSER_LIMIT", "keys"))?;
    if keys.len() > limits.max_key_count {
        return fail_msg("ERR_PARSER_LIMIT", "keys");
    }
    for k in keys {
        validate_key_record(k, limits)?;
    }
    let tombs = o
        .get("tombstones")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CkvfError::msg("ERR_PARSER_LIMIT", "tombstones"))?;
    if tombs.len() > limits.max_tombstones {
        return fail_msg("ERR_PARSER_LIMIT", "tombstones");
    }
    validate_extensions(
        o.get("extensions").unwrap_or(&Value::Array(vec![])),
        false,
        limits,
    )?;
    validate_extensions(
        o.get("critical_extensions")
            .unwrap_or(&Value::Array(vec![])),
        true,
        limits,
    )?;
    VaultPayload::from_json(raw).ok_or_else(|| CkvfError::msg("ERR_FORMAT", "payload"))
}

pub fn validate_key_record(raw: &Value, limits: ParserLimits) -> Result<KeyRecord, CkvfError> {
    let o = as_object(raw, "key record")?;
    reject_unknown_keys(
        o,
        &[
            "absolute_key_id",
            "short_key_id",
            "family",
            "algorithm",
            "algorithm_suite",
            "encoding",
            "purpose",
            "public_key",
            "private_key",
            "created_at",
            "status",
            "metadata",
        ],
    )?;
    let family = o
        .get("family")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::new("ERR_FAMILY"))?;
    if is_forbidden_family(family) || !key_families_contains(family) {
        return fail_msg("ERR_FAMILY", family);
    }
    let encoding = o
        .get("encoding")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::new("ERR_ENCODING"))?;
    if !key_encodings_contains(encoding) {
        return fail_msg("ERR_ENCODING", encoding);
    }
    if family == "openpgp" && encoding != "openpgp-tsk" {
        return fail_msg("ERR_ENCODING", "openpgp requires openpgp-tsk");
    }
    if family == "smime" && encoding == "openpgp-tsk" {
        return fail_msg("ERR_ENCODING", "smime cannot use openpgp-tsk");
    }
    if let Some(suite) = o.get("algorithm_suite") {
        if !suite.is_null() {
            let s = suite
                .as_str()
                .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "algorithm_suite"))?;
            if !algorithm_suites_contains(s) {
                return fail_msg("ERR_FORMAT", "algorithm_suite");
            }
        }
    }
    let purpose = o
        .get("purpose")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "purpose"))?;
    if purpose.is_empty() {
        return fail_msg("ERR_FORMAT", "purpose");
    }
    let mut seen = HashSet::new();
    for p in purpose {
        let ps = p
            .as_str()
            .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "purpose"))?;
        if !key_purposes_contains(ps) {
            return fail_msg("ERR_FORMAT", "purpose");
        }
        if !seen.insert(ps) {
            return fail_msg("ERR_FORMAT", "duplicate purpose");
        }
    }
    let status = o
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::new("ERR_STATUS"))?;
    if !key_statuses_contains(status) {
        return fail("ERR_STATUS");
    }
    let public_key = o
        .get("public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::msg("ERR_ENCODING", "public_key"))?;
    let pub_bytes = decode_b64_len(public_key, None)?;
    if pub_bytes.len() > limits.max_key_bytes {
        return fail_msg("ERR_PARSER_LIMIT", "public_key");
    }
    if let Some(pk) = o.get("private_key") {
        if !pk.is_null() {
            let s = pk
                .as_str()
                .ok_or_else(|| CkvfError::msg("ERR_ENCODING", "private_key"))?;
            let priv_bytes = decode_b64_len(s, None)?;
            if priv_bytes.len() > limits.max_key_bytes {
                return fail_msg("ERR_PARSER_LIMIT", "private_key");
            }
        }
    }
    let short_id = o
        .get("short_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CkvfError::new("ERR_SHORT_KEY_ID"))?;
    static SHORT_RE: OnceLock<Regex> = OnceLock::new();
    let re = SHORT_RE.get_or_init(|| Regex::new(r"^[0-9A-F]{4}-[0-9A-F]{4}$").unwrap());
    if !re.is_match(short_id) {
        return fail("ERR_SHORT_KEY_ID");
    }
    if let Some(meta) = o.get("metadata") {
        if let Some(m) = meta.as_object() {
            if !m.is_empty() {
                return fail_msg(
                    "ERR_FORMAT",
                    "unregistered key metadata; use extensions",
                );
            }
        } else if !meta.is_null() {
            return fail_msg(
                "ERR_FORMAT",
                "unregistered key metadata; use extensions",
            );
        }
    }
    KeyRecord::from_json(raw).ok_or_else(|| CkvfError::msg("ERR_FORMAT", "key record"))
}

pub fn validate_extensions(
    raw: &Value,
    critical: bool,
    limits: ParserLimits,
) -> Result<Vec<Extension>, CkvfError> {
    let arr = raw
        .as_array()
        .ok_or_else(|| CkvfError::msg("ERR_EXTENSION", "extensions must be an array"))?;
    if arr.len() > limits.max_extensions {
        return fail_msg("ERR_PARSER_LIMIT", "too many extensions");
    }
    static ID_RE: OnceLock<Regex> = OnceLock::new();
    let id_re = ID_RE.get_or_init(|| Regex::new(r"^(std|exp|priv):[a-z0-9][a-z0-9._-]*$").unwrap());
    let mut out = Vec::with_capacity(arr.len());
    for e in arr {
        let o = as_object(e, "extension")?;
        reject_unknown_keys(o, &["id", "critical", "data"])?;
        let id = o
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CkvfError::msg("ERR_EXTENSION", "id"))?;
        if !id_re.is_match(id) {
            return fail_msg("ERR_EXTENSION", "id");
        }
        if o.get("critical").and_then(|v| v.as_bool()) != Some(critical) {
            return fail_msg("ERR_EXTENSION", "critical flag mismatch");
        }
        if !o.contains_key("data") {
            return fail_msg("ERR_EXTENSION", "data required");
        }
        let encoded = serde_json::to_string(o.get("data").unwrap())
            .map_err(|_| CkvfError::msg("ERR_EXTENSION", "data"))?;
        if encoded.len() > limits.max_extension_bytes {
            return fail_msg("ERR_PARSER_LIMIT", "extension too large");
        }
        if critical {
            return fail_msg(
                "ERR_CRITICAL_EXTENSION",
                format!("unknown critical extension {id}"),
            );
        }
        out.push(
            Extension::from_json(e).ok_or_else(|| CkvfError::msg("ERR_EXTENSION", "extension"))?,
        );
    }
    Ok(out)
}

pub fn is_rfc3339_z(s: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$").unwrap()
    });
    re.is_match(s)
}

pub fn decode_b64_len(s: &str, expected: Option<usize>) -> Result<Vec<u8>, CkvfError> {
    let bytes = b64::decode(s).map_err(|e| CkvfError::msg("ERR_BASE64", e.0))?;
    if let Some(n) = expected {
        if bytes.len() != n {
            return fail_msg(
                "ERR_BASE64",
                format!("expected {n} bytes, got {}", bytes.len()),
            );
        }
    }
    Ok(bytes)
}

pub fn default_parse(text: &str) -> Result<VaultContainer, CkvfError> {
    let raw = parse_json_limited(text, DEFAULT_LIMITS)?;
    validate_container_shape(&raw, DEFAULT_LIMITS)
}
