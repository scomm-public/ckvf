//! Container version and capability surface.

use crate::registries::UNLOCK_METHODS;
use crate::types::CKVF_CONTAINER_VERSION;

pub const READ_VERSIONS: &[&str] = &[CKVF_CONTAINER_VERSION];
pub const WRITE_VERSIONS: &[&str] = &[CKVF_CONTAINER_VERSION];

pub fn can_read_version(version: &str) -> bool {
    READ_VERSIONS.contains(&version)
}

pub fn can_write_version(version: &str) -> bool {
    WRITE_VERSIONS.contains(&version)
}

pub fn default_write_version() -> &'static str {
    CKVF_CONTAINER_VERSION
}

pub fn supported_algorithms() -> &'static [&'static str] {
    &[
        "Ed25519",
        "Ed448",
        "X25519",
        "X448",
        "NIST-P-256",
        "NIST-P-384",
        "NIST-P-521",
        "RSA-2048",
        "RSA-3072",
        "RSA-4096",
        "ML-KEM-768",
        "ML-DSA-65",
        "SLH-DSA-SHA2-128s",
    ]
}

pub fn supported_key_encodings() -> &'static [&'static str] {
    &["openpgp-tsk", "pkcs8", "pkcs12"]
}

pub fn supported_unlock_methods() -> &'static [&'static str] {
    UNLOCK_METHODS
}

pub fn supported_operations() -> &'static [&'static str] {
    &[
        "ADD_KEY",
        "RETIRE_KEY",
        "REVOKE_KEY",
        "SET_PREFERRED_KEY",
        "ADD_DEVICE",
        "REMOVE_DEVICE",
        "COMMIT_VAULT_GENERATION",
        "MERGE_VAULT",
        "UPDATE_METADATA",
        "DELETE_PRIVATE_KEY",
        "ESTABLISH_MSK",
        "REPLACE_MSK",
    ]
}
