//! Software crypto matching DartCkvfCrypto (Argon2id, AES-256-GCM, Ed25519, SHA-256).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::errors::{fail, CkvfError};

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

pub struct AesGcmResult {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn aes256gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AesGcmResult, CkvfError> {
    if key.len() != 32 || iv.len() != 12 {
        return fail("ERR_FORMAT");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CkvfError::new("ERR_INTERNAL"))?;
    let nonce = Nonce::from_slice(iv);
    let sealed = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CkvfError::new("ERR_INTERNAL"))?;
    if sealed.len() < 16 {
        return fail("ERR_INTERNAL");
    }
    let split = sealed.len() - 16;
    Ok(AesGcmResult {
        ciphertext: sealed[..split].to_vec(),
        tag: sealed[split..].to_vec(),
    })
}

pub fn aes256gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CkvfError> {
    if key.len() != 32 || iv.len() != 12 || tag.len() != 16 {
        return fail("ERR_AEAD_DECRYPT");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CkvfError::new("ERR_AEAD_DECRYPT"))?;
    let nonce = Nonce::from_slice(iv);
    let mut sealed = Vec::with_capacity(ciphertext.len() + tag.len());
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed,
                aad,
            },
        )
        .map_err(|_| CkvfError::new("ERR_AEAD_DECRYPT"))
}

/// Argon2id with `m` in KiB (matches package:cryptography / DartCkvfCrypto).
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
    key_length: u32,
) -> Result<Vec<u8>, CkvfError> {
    let params = Params::new(m, t, p, Some(key_length as usize))
        .map_err(|_| CkvfError::msg("ERR_KDF", "invalid Argon2id params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; key_length as usize];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CkvfError::msg("ERR_KDF", "Argon2id failed"))?;
    Ok(out)
}

pub struct Ed25519KeyPair {
    pub public_key: Vec<u8>,
    /// 32-byte seed (matches Dart extractPrivateKeyBytes).
    pub private_key: Vec<u8>,
}

pub fn ed25519_generate() -> Ed25519KeyPair {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    ed25519_from_seed(&seed)
}

pub fn ed25519_from_seed(seed: &[u8]) -> Ed25519KeyPair {
    let mut s = [0u8; 32];
    s.copy_from_slice(&seed[..32]);
    let signing = SigningKey::from_bytes(&s);
    let verifying = signing.verifying_key();
    Ed25519KeyPair {
        public_key: verifying.to_bytes().to_vec(),
        private_key: s.to_vec(),
    }
}

pub fn ed25519_public_from_seed(seed: &[u8]) -> Vec<u8> {
    ed25519_from_seed(seed).public_key
}

pub fn ed25519_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, CkvfError> {
    if seed.len() != 32 {
        return fail("ERR_FORMAT");
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    let signing = SigningKey::from_bytes(&s);
    Ok(signing.sign(message).to_bytes().to_vec())
}

pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(public_key);
    let Ok(verifying) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    verifying.verify(message, &sig).is_ok()
}
