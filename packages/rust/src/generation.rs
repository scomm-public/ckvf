//! Generation hash computation and checks.

use crate::aad::container_without_generation_hash;
use crate::b64;
use crate::crypto::{constant_time_equal, sha256};
use crate::errors::{fail_msg, CkvfError};
use crate::jcs;
use crate::types::VaultContainer;

pub fn compute_generation_hash(container: &VaultContainer) -> Result<String, CkvfError> {
    let body = container_without_generation_hash(container);
    let bytes = jcs::canonicalize_bytes(&body).map_err(|e| CkvfError::msg("ERR_JCS", e.0))?;
    Ok(b64::encode(&sha256(&bytes)))
}

pub fn assert_generation_hash(container: &VaultContainer) -> Result<(), CkvfError> {
    let expected = compute_generation_hash(container)?;
    let actual = decode_hash(&container.generation_hash)?;
    let exp = decode_hash(&expected)?;
    if !constant_time_equal(&actual, &exp) {
        return fail_msg("ERR_GENERATION_HASH", "generation_hash mismatch");
    }
    Ok(())
}

fn decode_hash(s: &str) -> Result<Vec<u8>, CkvfError> {
    let bytes = b64::decode(s).map_err(|e| CkvfError::msg("ERR_BASE64", e.0))?;
    if bytes.len() != 32 {
        return fail_msg("ERR_BASE64", format!("expected 32 bytes, got {}", bytes.len()));
    }
    Ok(bytes)
}

pub fn detect_stale_generation(local: &VaultContainer, remote_head: &VaultContainer) -> Result<(), CkvfError> {
    if local.vault_id != remote_head.vault_id {
        return fail_msg("ERR_FORMAT", "vault_id mismatch");
    }
    if local.generation < remote_head.generation {
        return fail_msg("ERR_STALE_GENERATION", "local generation is behind head");
    }
    Ok(())
}

pub fn detect_generation_conflict(a: &VaultContainer, b: &VaultContainer) -> Result<(), CkvfError> {
    if a.vault_id != b.vault_id {
        return fail_msg("ERR_FORMAT", "vault_id mismatch");
    }
    if a.generation == b.generation && a.generation_hash != b.generation_hash {
        return fail_msg(
            "ERR_GENERATION_CONFLICT",
            "same generation, different generation_hash",
        );
    }
    Ok(())
}
