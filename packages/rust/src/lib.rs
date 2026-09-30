//! Cryptographic Key Vault Format (CKVF) reference SDK.
//!
//! Container create, encrypt, decrypt, and merge for version `"1.0"`.
//! JSON canonicalization and unpadded base64url are also exported as a C ABI
//! (`scomm_vault_*`) plus an optional WASM build of the same functions.
//! This crate does not speak Discovery HTTP or the identity OPRF.

mod aad;
mod b64;
mod crypto;
mod custody;
mod errors;
mod ffi;
mod generation;
mod identity;
mod jcs;
mod keyid;
mod limits;
mod merge;
mod openpgp;
mod operations;
mod pkcs8;
mod registries;
mod slots;
mod types;
mod validate;
mod vault;
mod version;

#[cfg(feature = "wasm")]
mod wasm_api;

pub use aad::{aad_object, container_without_generation_hash, slot_fingerprint, vault_aad, wrap_aad};
pub use b64::{decode as base64url_decode, encode as base64url_encode, B64Error};
pub use crypto::{
    aes256gcm_decrypt, aes256gcm_encrypt, argon2id, constant_time_equal, ed25519_from_seed,
    ed25519_generate, ed25519_public_from_seed, ed25519_sign, ed25519_verify, random_bytes, sha256,
    AesGcmResult, Ed25519KeyPair,
};
pub use custody::{is_understood_critical_extension, KEY_CUSTODY_EXTENSION_ID};
pub use errors::{fail, fail_msg, CkvfError, ERROR_CODES};
pub use generation::{
    assert_generation_hash, compute_generation_hash, detect_generation_conflict,
    detect_stale_generation,
};
pub use identity::{
    assert_identity, canonicalize_dns, canonicalize_email, identity_id, make_identity,
};
pub use jcs::{canonicalize, canonicalize_bytes, canonicalize_json, JcsError};
pub use keyid::{
    absolute_key_id, canonical_public_key_bytes, key_ids, msk_id, short_key_id,
    short_key_id_from_digest,
};
pub use limits::{
    Argon2idParams, ParserLimits, DEFAULT_LIMITS, PEPPER_MIN_ARGON2ID, RECOMMENDED_ARGON2ID,
    TEST_ARGON2ID,
};
pub use merge::merge_payloads;
pub use openpgp::{
    build_openpgp_ed25519_public, build_openpgp_ed25519_tsk, canonical_openpgp_public_key,
    encode_new_format_packet,
};
pub use operations::{apply_operation, construct_operation, verify_operation};
pub use pkcs8::{build_pkcs8_ed25519, build_spki_ed25519, spki_from_pkcs8};
pub use registries::{
    algorithm_suite_from_algorithm, is_forbidden_family, status_severity, AEAD_ALGORITHMS,
    ALGORITHM_SUITES, FORBIDDEN_FAMILIES, IDENTITY_TYPES, KDFS, KEY_ENCODINGS, KEY_FAMILIES,
    KEY_PURPOSES, KEY_STATUSES, MSK_ALGORITHMS, PEPPER_UNLOCK_METHODS, UNLOCK_METHODS,
};
pub use slots::{
    add_device_slot, add_pepper_slot, canonical_recovery_code, generate_recovery_code,
    open_vault_with_device_kek, open_vault_with_pepper, pepper_secret, rewrap_pepper_slot,
    wrap_device_slot, wrap_pepper_slot, PepperKey, PepperOprf, DEVICE_WRAP_METHOD,
    PASSWORD_OPRF_METHOD, RECOVERY_CODE_OPRF_METHOD,
};
pub use types::*;
pub use validate::{
    decode_b64_len, default_parse, is_rfc3339_z, parse_json_limited, reject_unknown_keys,
    validate_container_shape, validate_extensions, validate_key_record, validate_payload_shape,
    validate_unlock_slot,
};
pub use vault::{
    add_test_openpgp_key, add_test_pkcs8_key, add_unlock_slot, change_password, commit_unlock_slots,
    create_vault, delete_private_key, export_private_key, find_keys_by_short_id, get_key,
    import_private_key, inspect_public_metadata, lock_vault, merge_onto, merge_vaults, open_vault,
    open_vault_str, open_vault_with, rechain, remove_unlock_slot, replace_msk, retire_key,
    revoke_key, rotate_vek, rfc3339, serialize_container, set_preferred_key, update_extensions,
    wrap_password_slot, CreateVaultOptions,
};
pub use version::{
    can_read_version, can_write_version, default_write_version, supported_algorithms,
    supported_key_encodings, supported_operations, supported_unlock_methods, READ_VERSIONS,
    WRITE_VERSIONS,
};

/// Parse outer container JSON without decrypting.
pub fn parse(source: &str) -> Result<VaultContainer, CkvfError> {
    let raw = parse_json_limited(source, DEFAULT_LIMITS)?;
    validate_container_shape(&raw, DEFAULT_LIMITS)
}

/// Validate container structure, encodings, and `generation_hash` (fail closed).
pub fn validate(container: &VaultContainer) -> Result<(), CkvfError> {
    let shaped = validate_container_shape(&container.to_json(), DEFAULT_LIMITS)?;
    assert_generation_hash(&shaped)
}

/// Create a new vault bound to an identity and wrap the VEK with `password`.
pub fn create(
    identity_type: &str,
    identity_value: &str,
    password: &str,
    now: Option<&str>,
) -> Result<UnlockedVault, CkvfError> {
    create_vault(CreateVaultOptions {
        identity_type,
        identity_value,
        password: Some(password),
        now,
        kdf: Some(TEST_ARGON2ID),
        vault_id: None,
        msk_seed: None,
        extensions: vec![],
        extra_slots: None,
    })
}

/// Encrypt / lock: reseal payload under the VEK.
pub fn encrypt(unlocked: &UnlockedVault) -> Result<VaultContainer, CkvfError> {
    lock_vault(unlocked)
}

/// Decrypt / open with a password. MUST NOT rewrite on open.
pub fn decrypt(source: &str, password: &str) -> Result<UnlockedVault, CkvfError> {
    open_vault_str(source, password, None, None)
}

/// Deterministic merge of two unlocked vaults.
pub fn merge(
    a: &UnlockedVault,
    b: &UnlockedVault,
    now: Option<&str>,
) -> Result<UnlockedVault, CkvfError> {
    merge_vaults(a, b, now)
}
