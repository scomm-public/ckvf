//! Signed vault operations (MSK Ed25519).

use std::collections::HashSet;

use serde_json::Value;

use crate::b64;
use crate::crypto::{ed25519_sign, ed25519_verify, random_bytes, sha256};
use crate::errors::{fail, fail_msg, CkvfError};
use crate::jcs;
use crate::types::{
    KeyRecord, OperationSignature, SignedBody, SignedOperation, Tombstone, VaultMetadata,
    VaultPayload, CKVF_PROTOCOL, CKVF_PROTOCOL_VERSION,
};
use crate::validate::{decode_b64_len, is_rfc3339_z};

pub fn construct_operation(
    operation: &str,
    identity_id: &str,
    vault_id: &str,
    generation: u64,
    timestamp: &str,
    payload: Value,
    msk_private_seed: &[u8],
    msk_id: &str,
    nonce: Option<&[u8]>,
) -> Result<SignedOperation, CkvfError> {
    if !is_rfc3339_z(timestamp) {
        return fail_msg("ERR_FORMAT", "timestamp");
    }
    let n = match nonce {
        Some(n) => n.to_vec(),
        None => random_bytes(32),
    };
    if n.len() != 32 {
        return fail_msg("ERR_FORMAT", "nonce must be 32 bytes");
    }
    let payload_bytes =
        jcs::canonicalize_bytes(&payload).map_err(|e| CkvfError::msg("ERR_JCS", e.0))?;
    let payload_hash = b64::encode(&sha256(&payload_bytes));
    let body = SignedBody {
        protocol: CKVF_PROTOCOL.into(),
        protocol_version: CKVF_PROTOCOL_VERSION.into(),
        operation: operation.into(),
        identity_id: identity_id.into(),
        vault_id: vault_id.into(),
        generation,
        nonce: b64::encode(&n),
        timestamp: timestamp.into(),
        payload_hash,
    };
    let body_bytes =
        jcs::canonicalize_bytes(&body.to_json()).map_err(|e| CkvfError::msg("ERR_JCS", e.0))?;
    let sig = ed25519_sign(msk_private_seed, &body_bytes)?;
    Ok(SignedOperation {
        body,
        payload,
        signature: OperationSignature {
            algorithm: "Ed25519".into(),
            msk_id: msk_id.into(),
            value: b64::encode(&sig),
        },
    })
}

pub fn verify_operation(
    envelope: &SignedOperation,
    public_key: &[u8],
    expected_msk_id: &str,
    replay_seen: Option<&mut HashSet<String>>,
) -> Result<(), CkvfError> {
    let body = &envelope.body;
    if body.protocol != CKVF_PROTOCOL {
        return fail_msg("ERR_OPERATION", "protocol");
    }
    if body.protocol_version != CKVF_PROTOCOL_VERSION {
        return fail_msg("ERR_VERSION", "protocol_version");
    }
    let payload_bytes =
        jcs::canonicalize_bytes(&envelope.payload).map_err(|e| CkvfError::msg("ERR_JCS", e.0))?;
    let payload_hash = b64::encode(&sha256(&payload_bytes));
    if payload_hash != body.payload_hash {
        return fail("ERR_PAYLOAD_HASH");
    }
    if envelope.signature.algorithm != "Ed25519" {
        return fail_msg("ERR_SIGNATURE", "algorithm");
    }
    let recover = body.operation == "REPLACE_MSK" || body.operation == "ESTABLISH_MSK";
    if !recover && envelope.signature.msk_id != expected_msk_id {
        return fail_msg("ERR_SIGNATURE", "msk_id");
    }
    if let Some(seen) = replay_seen {
        if seen.contains(&body.nonce) {
            return fail("ERR_REPLAY");
        }
        seen.insert(body.nonce.clone());
    }
    let body_bytes =
        jcs::canonicalize_bytes(&body.to_json()).map_err(|e| CkvfError::msg("ERR_JCS", e.0))?;
    let sig = decode_b64_len(&envelope.signature.value, Some(64))?;
    if !ed25519_verify(public_key, &body_bytes, &sig) {
        return fail("ERR_SIGNATURE");
    }
    Ok(())
}

pub fn apply_operation(
    payload: &VaultPayload,
    envelope: &SignedOperation,
    now: &str,
) -> Result<VaultPayload, CkvfError> {
    let op = envelope.body.operation.as_str();
    let p = &envelope.payload;
    match op {
        "RETIRE_KEY" | "REVOKE_KEY" => {
            let id = p
                .get("absolute_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let status = if op == "RETIRE_KEY" {
                "retired"
            } else {
                "revoked"
            };
            Ok(VaultPayload {
                identity: payload.identity.clone(),
                msk: payload.msk.clone(),
                keys: payload
                    .keys
                    .iter()
                    .map(|k| {
                        if k.absolute_key_id == id {
                            k.copy_with(Some(status), None, None)
                        } else {
                            k.clone()
                        }
                    })
                    .collect(),
                preferred_keys: payload.preferred_keys.clone(),
                metadata: VaultMetadata {
                    created_at: payload.metadata.created_at.clone(),
                    updated_at: now.into(),
                },
                tombstones: payload.tombstones.clone(),
                extensions: payload.extensions.clone(),
                critical_extensions: payload.critical_extensions.clone(),
            })
        }
        "SET_PREFERRED_KEY" => {
            let family = p
                .get("family")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "family"))?;
            let purpose = p
                .get("purpose")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "purpose"))?;
            let mut preferred = payload.preferred_keys.clone();
            let entry = preferred
                .entry(family.to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            let obj = entry
                .as_object_mut()
                .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "preferred_keys"))?;
            match p.get("absolute_key_id") {
                None | Some(Value::Null) => {
                    obj.remove(purpose);
                }
                Some(v) => {
                    obj.insert(
                        purpose.to_string(),
                        Value::String(v.as_str().unwrap_or("").to_string()),
                    );
                }
            }
            Ok(VaultPayload {
                identity: payload.identity.clone(),
                msk: payload.msk.clone(),
                keys: payload.keys.clone(),
                preferred_keys: preferred,
                metadata: VaultMetadata {
                    created_at: payload.metadata.created_at.clone(),
                    updated_at: now.into(),
                },
                tombstones: payload.tombstones.clone(),
                extensions: payload.extensions.clone(),
                critical_extensions: payload.critical_extensions.clone(),
            })
        }
        "DELETE_PRIVATE_KEY" => {
            let id = p
                .get("absolute_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let reason = p
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("user-requested");
            let mut tombstones = payload.tombstones.clone();
            tombstones.push(Tombstone {
                absolute_key_id: id.clone(),
                deleted_at: now.into(),
                nonce: envelope.body.nonce.clone(),
                reason: reason.into(),
            });
            Ok(VaultPayload {
                identity: payload.identity.clone(),
                msk: payload.msk.clone(),
                keys: payload
                    .keys
                    .iter()
                    .map(|k| {
                        if k.absolute_key_id == id {
                            k.copy_with(None, Some(None), None)
                        } else {
                            k.clone()
                        }
                    })
                    .collect(),
                preferred_keys: payload.preferred_keys.clone(),
                metadata: VaultMetadata {
                    created_at: payload.metadata.created_at.clone(),
                    updated_at: now.into(),
                },
                tombstones,
                extensions: payload.extensions.clone(),
                critical_extensions: payload.critical_extensions.clone(),
            })
        }
        "ADD_KEY" => {
            let key = KeyRecord::from_json(
                p.get("key")
                    .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "key"))?,
            )
            .ok_or_else(|| CkvfError::msg("ERR_FORMAT", "key"))?;
            if payload.keys.iter().any(|k| k.absolute_key_id == key.absolute_key_id) {
                return fail_msg("ERR_KEY_ID", "duplicate key");
            }
            let mut keys = payload.keys.clone();
            keys.push(key);
            Ok(VaultPayload {
                identity: payload.identity.clone(),
                msk: payload.msk.clone(),
                keys,
                preferred_keys: payload.preferred_keys.clone(),
                metadata: VaultMetadata {
                    created_at: payload.metadata.created_at.clone(),
                    updated_at: now.into(),
                },
                tombstones: payload.tombstones.clone(),
                extensions: payload.extensions.clone(),
                critical_extensions: payload.critical_extensions.clone(),
            })
        }
        _ => Ok(VaultPayload {
            identity: payload.identity.clone(),
            msk: payload.msk.clone(),
            keys: payload.keys.clone(),
            preferred_keys: payload.preferred_keys.clone(),
            metadata: VaultMetadata {
                created_at: payload.metadata.created_at.clone(),
                updated_at: now.into(),
            },
            tombstones: payload.tombstones.clone(),
            extensions: payload.extensions.clone(),
            critical_extensions: payload.critical_extensions.clone(),
        }),
    }
}
