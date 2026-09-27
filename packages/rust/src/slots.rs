//! Device and pepper unlock slots.

use unicode_normalization::UnicodeNormalization;

use crate::aad::wrap_aad;
use crate::b64;
use crate::crypto::{aes256gcm_decrypt, aes256gcm_encrypt, argon2id, random_bytes};
use crate::errors::{fail, fail_msg, CkvfError};
use crate::limits::{Argon2idParams, ParserLimits, PEPPER_MIN_ARGON2ID};
use crate::registries::PEPPER_UNLOCK_METHODS;
use crate::types::{
    KdfParams, OprfParams, UnlockSlot, UnlockedVault, VaultContainer, WrapParams,
};
use crate::vault::{commit_unlock_slots, open_vault_with, rfc3339};
use serde_json::Value;

pub const DEVICE_WRAP_METHOD: &str = "device-wrap-a256gcm";
pub const PASSWORD_OPRF_METHOD: &str = "password-oprf-argon2id";
pub const RECOVERY_CODE_OPRF_METHOD: &str = "recovery-code-oprf-argon2id";

pub struct PepperKey {
    pub kid: String,
    pub public_key: Vec<u8>,
}

/// Host POPRF finalize (profiles/pepper-oprf.md). Implementations talk to the host.
pub trait PepperOprf {
    fn finalize(
        &self,
        vault_id: &str,
        slot_id: &str,
        kid: &str,
        public_key: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>, CkvfError>;
}

pub fn pepper_secret(method: &str, secret: &str) -> Result<Vec<u8>, CkvfError> {
    if method == RECOVERY_CODE_OPRF_METHOD {
        return Ok(canonical_recovery_code(secret)?.into_bytes());
    }
    if method == PASSWORD_OPRF_METHOD {
        let nfc: String = secret.nfc().collect();
        return Ok(nfc.into_bytes());
    }
    fail_msg("ERR_UNLOCK", "not a pepper method")
}

const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn generate_recovery_code() -> String {
    let bytes = random_bytes(17);
    let mut bits = 0u32;
    let mut acc = 0u32;
    let mut out = String::new();
    for b in bytes {
        acc = (acc << 8) | (b as u32);
        bits += 8;
        while bits >= 5 && out.len() < 26 {
            bits -= 5;
            out.push(BASE32[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    let mut groups = Vec::new();
    let mut i = 0;
    while i < out.len() {
        let end = (i + 5).min(out.len());
        groups.push(&out[i..end]);
        i += 5;
    }
    groups.join("-")
}

pub fn canonical_recovery_code(code: &str) -> Result<String, CkvfError> {
    let c: String = code
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if c.len() != 26 || !c.bytes().all(|b| BASE32.contains(&b)) {
        return fail_msg("ERR_UNLOCK", "recovery code must be 26 Base32 characters");
    }
    Ok(c)
}

fn pepper_kek(
    vault_id: &str,
    slot_id: &str,
    method: &str,
    secret: &str,
    pepper: &dyn PepperOprf,
    oprf: &OprfParams,
    kdf: &KdfParams,
) -> Result<Vec<u8>, CkvfError> {
    let secret_bytes = pepper_secret(method, secret)?;
    let rwd = pepper.finalize(
        vault_id,
        slot_id,
        &oprf.kid,
        &b64::decode(&oprf.public_key).map_err(|e| CkvfError::msg("ERR_BASE64", e.0))?,
        &secret_bytes,
    )?;
    if rwd.len() != 64 {
        return fail_msg("ERR_UNLOCK", "pepper output must be 64 bytes");
    }
    let mut password = rwd;
    password.extend_from_slice(&secret_bytes);
    argon2id(
        &password,
        &b64::decode(&kdf.salt).map_err(|e| CkvfError::msg("ERR_BASE64", e.0))?,
        kdf.m,
        kdf.t,
        kdf.p,
        kdf.key_length,
    )
}

fn wrap(
    kek: &[u8],
    vek: &[u8],
    method: &str,
    slot_id: &str,
    vault_id: &str,
) -> Result<WrapParams, CkvfError> {
    let iv = random_bytes(12);
    let wrapped = aes256gcm_encrypt(kek, &iv, vek, &wrap_aad(method, slot_id, vault_id)?)?;
    Ok(WrapParams {
        alg: "A256GCM".into(),
        iv: b64::encode(&iv),
        ciphertext: b64::encode(&wrapped.ciphertext),
        tag: b64::encode(&wrapped.tag),
    })
}

fn unwrap_slot(kek: &[u8], slot: &UnlockSlot, vault_id: &str) -> Result<Vec<u8>, CkvfError> {
    aes256gcm_decrypt(
        kek,
        &crate::validate::decode_b64_len(&slot.wrap.iv, Some(12))?,
        &crate::validate::decode_b64_len(&slot.wrap.ciphertext, Some(32))?,
        &crate::validate::decode_b64_len(&slot.wrap.tag, Some(16))?,
        &wrap_aad(&slot.method, &slot.slot_id, vault_id)?,
    )
    .map_err(|_| CkvfError::new("ERR_WRAP_DECRYPT"))
}

fn slot_by_id(
    container: &VaultContainer,
    slot_id: &str,
    methods: &[&str],
) -> Result<UnlockSlot, CkvfError> {
    for s in &container.unlock_slots {
        if s.slot_id == slot_id {
            if !methods.contains(&s.method.as_str()) {
                return fail_msg("ERR_UNLOCK", "slot method");
            }
            return Ok(s.clone());
        }
    }
    fail("ERR_SLOT_ID")
}

pub fn wrap_pepper_slot(
    vault_id: &str,
    vek: &[u8],
    method: &str,
    secret: &str,
    pepper: &dyn PepperOprf,
    key: &PepperKey,
    kdf: Argon2idParams,
    slot_id: Option<&str>,
    now: Option<&str>,
) -> Result<UnlockSlot, CkvfError> {
    if !PEPPER_UNLOCK_METHODS.contains(&method) {
        return fail_msg("ERR_UNLOCK", "not a pepper method");
    }
    if kdf.m < PEPPER_MIN_ARGON2ID.m || kdf.t < PEPPER_MIN_ARGON2ID.t {
        return fail_msg("ERR_KDF", "pepper slots need m >= 65536 and t >= 3");
    }
    let id = slot_id
        .map(str::to_string)
        .unwrap_or_else(|| b64::encode(&random_bytes(16)));
    let oprf = OprfParams::new(&key.kid, b64::encode(&key.public_key));
    let kdf_params = KdfParams {
        alg: "Argon2id".into(),
        salt: b64::encode(&random_bytes(16)),
        m: kdf.m,
        t: kdf.t,
        p: kdf.p,
        key_length: 32,
    };
    let kek = pepper_kek(vault_id, &id, method, secret, pepper, &oprf, &kdf_params)?;
    Ok(UnlockSlot {
        slot_id: id.clone(),
        method: method.into(),
        created_at: rfc3339(now),
        kdf: Some(kdf_params),
        oprf: Some(oprf),
        wrap: wrap(&kek, vek, method, &id, vault_id)?,
    })
}

pub fn add_pepper_slot(
    unlocked: &UnlockedVault,
    method: &str,
    secret: &str,
    pepper: &dyn PepperOprf,
    key: &PepperKey,
    kdf: Argon2idParams,
    slot_id: Option<&str>,
    now: Option<&str>,
) -> Result<UnlockedVault, CkvfError> {
    let slot = wrap_pepper_slot(
        &unlocked.container.vault_id,
        &unlocked.vek,
        method,
        secret,
        pepper,
        key,
        kdf,
        slot_id,
        now,
    )?;
    let mut slots = unlocked.container.unlock_slots.clone();
    slots.push(slot);
    commit_unlock_slots(unlocked, slots)
}

pub fn open_vault_with_pepper(
    container_or_json: &Value,
    secret: &str,
    pepper: &dyn PepperOprf,
    method: &str,
    slot_id: Option<&str>,
    limits: Option<ParserLimits>,
) -> Result<UnlockedVault, CkvfError> {
    open_vault_with(container_or_json, limits, |container| {
        let candidates: Vec<UnlockSlot> = if let Some(id) = slot_id {
            vec![slot_by_id(container, id, PEPPER_UNLOCK_METHODS)?]
        } else {
            container
                .unlock_slots
                .iter()
                .filter(|s| s.method == method)
                .cloned()
                .collect()
        };
        if candidates.is_empty() {
            return fail_msg("ERR_UNLOCK", format!("no {method} slot"));
        }
        let last = candidates.len() - 1;
        for (i, slot) in candidates.iter().enumerate() {
            let kek = pepper_kek(
                &container.vault_id,
                &slot.slot_id,
                &slot.method,
                secret,
                pepper,
                slot.oprf.as_ref().unwrap(),
                slot.kdf.as_ref().unwrap(),
            )?;
            match unwrap_slot(&kek, slot, &container.vault_id) {
                Ok(v) => return Ok(v),
                Err(e) if e.code() == "ERR_WRAP_DECRYPT" && i != last => continue,
                Err(e) => return Err(e),
            }
        }
        fail("ERR_WRAP_DECRYPT")
    })
}

pub fn rewrap_pepper_slot(
    unlocked: &UnlockedVault,
    slot_id: &str,
    secret: &str,
    pepper: &dyn PepperOprf,
    key: &PepperKey,
    now: Option<&str>,
) -> Result<UnlockedVault, CkvfError> {
    let old = slot_by_id(&unlocked.container, slot_id, PEPPER_UNLOCK_METHODS)?;
    let kdf = old.kdf.as_ref().unwrap();
    let replacement = wrap_pepper_slot(
        &unlocked.container.vault_id,
        &unlocked.vek,
        &old.method,
        secret,
        pepper,
        key,
        Argon2idParams {
            alg: "Argon2id",
            m: kdf.m,
            t: kdf.t,
            p: kdf.p,
            key_length: 32,
        },
        Some(slot_id),
        now,
    )?;
    let slots = unlocked
        .container
        .unlock_slots
        .iter()
        .map(|s| {
            if s.slot_id == slot_id {
                replacement.clone()
            } else {
                s.clone()
            }
        })
        .collect();
    commit_unlock_slots(unlocked, slots)
}

pub fn wrap_device_slot(
    vault_id: &str,
    vek: &[u8],
    kek: &[u8],
    slot_id: Option<&str>,
    now: Option<&str>,
) -> Result<UnlockSlot, CkvfError> {
    if kek.len() != 32 {
        return fail_msg("ERR_UNLOCK", "device KEK must be 32 bytes");
    }
    let id = slot_id
        .map(str::to_string)
        .unwrap_or_else(|| b64::encode(&random_bytes(16)));
    Ok(UnlockSlot {
        slot_id: id.clone(),
        method: DEVICE_WRAP_METHOD.into(),
        created_at: rfc3339(now),
        kdf: None,
        oprf: None,
        wrap: wrap(kek, vek, DEVICE_WRAP_METHOD, &id, vault_id)?,
    })
}

pub fn add_device_slot(
    unlocked: &UnlockedVault,
    kek: &[u8],
    slot_id: Option<&str>,
    now: Option<&str>,
) -> Result<UnlockedVault, CkvfError> {
    let slot = wrap_device_slot(
        &unlocked.container.vault_id,
        &unlocked.vek,
        kek,
        slot_id,
        now,
    )?;
    let mut slots = unlocked.container.unlock_slots.clone();
    slots.push(slot);
    commit_unlock_slots(unlocked, slots)
}

pub fn open_vault_with_device_kek(
    container_or_json: &Value,
    slot_id: &str,
    kek: &[u8],
    limits: Option<ParserLimits>,
) -> Result<UnlockedVault, CkvfError> {
    open_vault_with(container_or_json, limits, |container| {
        let slot = slot_by_id(container, slot_id, &[DEVICE_WRAP_METHOD])?;
        unwrap_slot(kek, &slot, &container.vault_id)
    })
}
