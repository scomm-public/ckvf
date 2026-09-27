//! AEAD associated data construction (matches aad.dart).

use serde_json::{json, Value};

use crate::errors::CkvfError;
use crate::jcs;
use crate::types::{UnlockSlot, VaultContainer};

pub fn aad_object(container: &VaultContainer) -> Value {
    json!({
        "critical_extensions": container.critical_extensions.iter().map(|e| e.to_json()).collect::<Vec<_>>(),
        "crypto": { "aead": container.crypto.aead, "iv": container.crypto.iv },
        "extensions": container.extensions.iter().map(|e| e.to_json()).collect::<Vec<_>>(),
        "format": container.format,
        "generation": container.generation,
        "previous_generation_hash": container.previous_generation_hash,
        "unlock_slots": container.unlock_slots.iter().map(UnlockSlot::to_json).collect::<Vec<_>>(),
        "vault_id": container.vault_id,
        "version": container.version,
    })
}

pub fn vault_aad(container: &VaultContainer) -> Result<Vec<u8>, CkvfError> {
    jcs::canonicalize_bytes(&aad_object(container))
        .map_err(|e| CkvfError::msg("ERR_JCS", e.0))
}

pub fn wrap_aad(method: &str, slot_id: &str, vault_id: &str) -> Result<Vec<u8>, CkvfError> {
    let obj = json!({
        "method": method,
        "slot_id": slot_id,
        "vault_id": vault_id,
    });
    jcs::canonicalize_bytes(&obj).map_err(|e| CkvfError::msg("ERR_JCS", e.0))
}

pub fn container_without_generation_hash(container: &VaultContainer) -> Value {
    let mut json = container.to_json();
    if let Some(obj) = json.as_object_mut() {
        obj.remove("generation_hash");
    }
    json
}

pub fn slot_fingerprint(slot: &UnlockSlot) -> Result<String, CkvfError> {
    jcs::canonicalize(&slot.to_json()).map_err(|e| CkvfError::msg("ERR_JCS", e.0))
}
