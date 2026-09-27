//! Minimal PKCS#8 / SPKI builders for Ed25519 test keys.

use crate::errors::{fail_msg, CkvfError};

pub fn build_pkcs8_ed25519(seed: &[u8], _public_key: Option<&[u8]>) -> Result<Vec<u8>, CkvfError> {
    if seed.len() != 32 {
        return fail_msg("ERR_ENCODING", "Ed25519 seed must be 32 bytes");
    }
    let mut out = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    out.extend_from_slice(seed);
    Ok(out)
}

pub fn build_spki_ed25519(public_key: &[u8]) -> Result<Vec<u8>, CkvfError> {
    if public_key.len() != 32 {
        return fail_msg("ERR_ENCODING", "Ed25519 public key must be 32 bytes");
    }
    let mut out = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    out.extend_from_slice(public_key);
    Ok(out)
}

pub fn spki_from_pkcs8(pkcs8: &[u8]) -> Result<Vec<u8>, CkvfError> {
    if pkcs8.len() == 48 && pkcs8[0] == 0x30 && pkcs8[8] == 0x2b {
        return fail_msg(
            "ERR_ENCODING",
            "PKCS#8 lacks publicKey; supply canonical SPKI",
        );
    }
    fail_msg("ERR_ENCODING", "unsupported PKCS#8")
}
