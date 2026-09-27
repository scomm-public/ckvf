//! Absolute and short key IDs.

use crate::b64;
use crate::crypto::sha256;
use crate::errors::{fail_msg, CkvfError};
use crate::openpgp::canonical_openpgp_public_key;
use crate::pkcs8::spki_from_pkcs8;

const HEX: &[u8; 16] = b"0123456789ABCDEF";

pub fn absolute_key_id(canonical_public_key: &[u8]) -> String {
    b64::encode(&sha256(canonical_public_key))
}

pub fn short_key_id_from_digest(digest: &[u8]) -> Result<String, CkvfError> {
    if digest.len() < 4 {
        return fail_msg("ERR_SHORT_KEY_ID", "digest too short");
    }
    let mut hex = String::with_capacity(8);
    for i in 0..4 {
        let b = digest[i];
        hex.push(HEX[((b >> 4) & 15) as usize] as char);
        hex.push(HEX[(b & 15) as usize] as char);
    }
    Ok(format!("{}-{}", &hex[..4], &hex[4..8]))
}

pub fn short_key_id(canonical_public_key: &[u8]) -> Result<String, CkvfError> {
    short_key_id_from_digest(&sha256(canonical_public_key))
}

pub fn key_ids(canonical_public_key: &[u8]) -> Result<(String, String), CkvfError> {
    let digest = sha256(canonical_public_key);
    Ok((
        b64::encode(&digest),
        short_key_id_from_digest(&digest)?,
    ))
}

pub fn canonical_public_key_bytes(
    encoding: &str,
    public_key_b64: &str,
    private_key_b64: Option<&str>,
) -> Result<Vec<u8>, CkvfError> {
    let pub_bytes = b64::decode(public_key_b64).map_err(|e| CkvfError::msg("ERR_BASE64", e.0))?;
    if encoding == "openpgp-tsk" {
        let priv_bytes = private_key_b64
            .map(|s| b64::decode(s).map_err(|e| CkvfError::msg("ERR_BASE64", e.0)))
            .transpose()?;
        return canonical_openpgp_public_key(&pub_bytes, priv_bytes.as_deref());
    }
    if encoding == "pkcs8" || encoding == "pkcs12" {
        if looks_like_spki(&pub_bytes) {
            return Ok(pub_bytes);
        }
        if let Some(priv_b64) = private_key_b64 {
            if encoding == "pkcs8" {
                let priv_bytes =
                    b64::decode(priv_b64).map_err(|e| CkvfError::msg("ERR_BASE64", e.0))?;
                if let Ok(spki) = spki_from_pkcs8(&priv_bytes) {
                    return Ok(spki);
                }
            }
            return Ok(pub_bytes);
        }
        return Ok(pub_bytes);
    }
    fail_msg("ERR_ENCODING", format!("unsupported encoding {encoding}"))
}

fn looks_like_spki(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x30
}

pub fn msk_id(public_key: &[u8]) -> String {
    b64::encode(&sha256(public_key))
}
