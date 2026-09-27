//! CKVF container and payload types.
//!
//! `to_json` mirrors the Dart SDK serializers (field names, explicit nulls,
//! omitted optional unlock fields) so JCS bytes stay compatible.

use serde_json::{json, Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CKVF_FORMAT: &str = "CKVF";
pub const CKVF_CONTAINER_VERSION: &str = "1.0";
pub const CKVF_PROTOCOL: &str = "CKVF";
pub const CKVF_PROTOCOL_VERSION: &str = "1.0";
pub const SPEC_LABEL: &str = "draft-0.1";

#[derive(Debug, Clone)]
pub struct Extension {
    pub id: String,
    pub critical: bool,
    pub data: Value,
}

impl Extension {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "critical": self.critical,
            "data": self.data,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            id: o.get("id")?.as_str()?.to_string(),
            critical: o.get("critical")?.as_bool()?,
            data: o.get("data").cloned().unwrap_or(Value::Null),
        })
    }
}

#[derive(Debug, Clone)]
pub struct CryptoParams {
    pub aead: String,
    pub iv: String,
}

impl CryptoParams {
    pub fn to_json(&self) -> Value {
        json!({ "aead": self.aead, "iv": self.iv })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            aead: o.get("aead")?.as_str()?.to_string(),
            iv: o.get("iv")?.as_str()?.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct KdfParams {
    pub alg: String,
    pub salt: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub key_length: u32,
}

impl KdfParams {
    pub fn to_json(&self) -> Value {
        json!({
            "alg": self.alg,
            "salt": self.salt,
            "m": self.m,
            "t": self.t,
            "p": self.p,
            "key_length": self.key_length,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            alg: o.get("alg")?.as_str()?.to_string(),
            salt: o.get("salt")?.as_str()?.to_string(),
            m: o.get("m")?.as_u64()? as u32,
            t: o.get("t")?.as_u64()? as u32,
            p: o.get("p")?.as_u64()? as u32,
            key_length: o.get("key_length")?.as_u64()? as u32,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WrapParams {
    pub alg: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

impl WrapParams {
    pub fn to_json(&self) -> Value {
        json!({
            "alg": self.alg,
            "iv": self.iv,
            "ciphertext": self.ciphertext,
            "tag": self.tag,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            alg: o.get("alg")?.as_str()?.to_string(),
            iv: o.get("iv")?.as_str()?.to_string(),
            ciphertext: o.get("ciphertext")?.as_str()?.to_string(),
            tag: o.get("tag")?.as_str()?.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct OprfParams {
    pub suite: String,
    pub mode: String,
    pub kid: String,
    pub public_key: String,
}

impl OprfParams {
    pub fn new(kid: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            suite: "ristretto255-SHA512".into(),
            mode: "poprf".into(),
            kid: kid.into(),
            public_key: public_key.into(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "suite": self.suite,
            "mode": self.mode,
            "kid": self.kid,
            "public_key": self.public_key,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            suite: o.get("suite")?.as_str()?.to_string(),
            mode: o.get("mode")?.as_str()?.to_string(),
            kid: o.get("kid")?.as_str()?.to_string(),
            public_key: o.get("public_key")?.as_str()?.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct UnlockSlot {
    pub slot_id: String,
    pub method: String,
    pub created_at: String,
    pub kdf: Option<KdfParams>,
    pub oprf: Option<OprfParams>,
    pub wrap: WrapParams,
}

impl UnlockSlot {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("slot_id".into(), Value::String(self.slot_id.clone()));
        m.insert("method".into(), Value::String(self.method.clone()));
        m.insert("created_at".into(), Value::String(self.created_at.clone()));
        if let Some(ref kdf) = self.kdf {
            m.insert("kdf".into(), kdf.to_json());
        }
        if let Some(ref oprf) = self.oprf {
            m.insert("oprf".into(), oprf.to_json());
        }
        m.insert("wrap".into(), self.wrap.to_json());
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            slot_id: o.get("slot_id")?.as_str()?.to_string(),
            method: o.get("method")?.as_str()?.to_string(),
            created_at: o.get("created_at")?.as_str()?.to_string(),
            kdf: o.get("kdf").and_then(KdfParams::from_json),
            oprf: o.get("oprf").and_then(OprfParams::from_json),
            wrap: WrapParams::from_json(o.get("wrap")?)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VaultContainer {
    pub format: String,
    pub version: String,
    pub vault_id: String,
    pub generation: u64,
    pub previous_generation_hash: Option<String>,
    pub generation_hash: String,
    pub crypto: CryptoParams,
    pub unlock_slots: Vec<UnlockSlot>,
    pub ciphertext: String,
    pub tag: String,
    pub extensions: Vec<Extension>,
    pub critical_extensions: Vec<Extension>,
}

impl VaultContainer {
    pub fn to_json(&self) -> Value {
        json!({
            "format": self.format,
            "version": self.version,
            "vault_id": self.vault_id,
            "generation": self.generation,
            "previous_generation_hash": self.previous_generation_hash,
            "generation_hash": self.generation_hash,
            "crypto": self.crypto.to_json(),
            "unlock_slots": self.unlock_slots.iter().map(UnlockSlot::to_json).collect::<Vec<_>>(),
            "ciphertext": self.ciphertext,
            "tag": self.tag,
            "extensions": self.extensions.iter().map(Extension::to_json).collect::<Vec<_>>(),
            "critical_extensions": self.critical_extensions.iter().map(Extension::to_json).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let slots = o
            .get("unlock_slots")?
            .as_array()?
            .iter()
            .map(UnlockSlot::from_json)
            .collect::<Option<Vec<_>>>()?;
        let extensions = o
            .get("extensions")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(Extension::from_json).collect())
            .unwrap_or_default();
        let critical_extensions = o
            .get("critical_extensions")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(Extension::from_json).collect())
            .unwrap_or_default();
        Some(Self {
            format: o.get("format")?.as_str()?.to_string(),
            version: o.get("version")?.as_str()?.to_string(),
            vault_id: o.get("vault_id")?.as_str()?.to_string(),
            generation: o.get("generation")?.as_u64()?,
            previous_generation_hash: match o.get("previous_generation_hash") {
                Some(Value::Null) | None => None,
                Some(Value::String(s)) => Some(s.clone()),
                _ => return None,
            },
            generation_hash: o.get("generation_hash")?.as_str()?.to_string(),
            crypto: CryptoParams::from_json(o.get("crypto")?)?,
            unlock_slots: slots,
            ciphertext: o.get("ciphertext")?.as_str()?.to_string(),
            tag: o.get("tag")?.as_str()?.to_string(),
            extensions,
            critical_extensions,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub r#type: String,
    pub value: String,
    pub identity_id: String,
}

impl Identity {
    pub fn to_json(&self) -> Value {
        json!({
            "type": self.r#type,
            "value": self.value,
            "identity_id": self.identity_id,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            r#type: o.get("type")?.as_str()?.to_string(),
            value: o.get("value")?.as_str()?.to_string(),
            identity_id: o.get("identity_id")?.as_str()?.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct MskCurrent {
    pub msk_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
    pub activated_at: String,
}

impl MskCurrent {
    pub fn to_json(&self) -> Value {
        json!({
            "msk_id": self.msk_id,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "private_key": self.private_key,
            "activated_at": self.activated_at,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            msk_id: o.get("msk_id")?.as_str()?.to_string(),
            algorithm: o.get("algorithm")?.as_str()?.to_string(),
            public_key: o.get("public_key")?.as_str()?.to_string(),
            private_key: o.get("private_key")?.as_str()?.to_string(),
            activated_at: o.get("activated_at")?.as_str()?.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct MskHistoryEntry {
    pub msk_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub activated_at: String,
    pub retired_at: String,
}

impl MskHistoryEntry {
    pub fn to_json(&self) -> Value {
        json!({
            "msk_id": self.msk_id,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "activated_at": self.activated_at,
            "retired_at": self.retired_at,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            msk_id: o.get("msk_id")?.as_str()?.to_string(),
            algorithm: o.get("algorithm")?.as_str()?.to_string(),
            public_key: o.get("public_key")?.as_str()?.to_string(),
            activated_at: o.get("activated_at")?.as_str()?.to_string(),
            retired_at: o.get("retired_at")?.as_str()?.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct MskState {
    pub current: MskCurrent,
    pub history: Vec<MskHistoryEntry>,
}

impl MskState {
    pub fn to_json(&self) -> Value {
        json!({
            "current": self.current.to_json(),
            "history": self.history.iter().map(MskHistoryEntry::to_json).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let history = o
            .get("history")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(MskHistoryEntry::from_json).collect())
            .unwrap_or_default();
        Some(Self {
            current: MskCurrent::from_json(o.get("current")?)?,
            history,
        })
    }
}

#[derive(Debug, Clone)]
pub struct KeyRecord {
    pub absolute_key_id: String,
    pub short_key_id: String,
    pub family: String,
    pub algorithm: String,
    pub algorithm_suite: Option<String>,
    pub encoding: String,
    pub purpose: Vec<String>,
    pub public_key: String,
    pub private_key: Option<String>,
    pub created_at: String,
    pub status: String,
    pub metadata: Map<String, Value>,
}

impl KeyRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "absolute_key_id": self.absolute_key_id,
            "short_key_id": self.short_key_id,
            "family": self.family,
            "algorithm": self.algorithm,
            "algorithm_suite": self.algorithm_suite,
            "encoding": self.encoding,
            "purpose": self.purpose,
            "public_key": self.public_key,
            "private_key": self.private_key,
            "created_at": self.created_at,
            "status": self.status,
            "metadata": Value::Object(self.metadata.clone()),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let purpose = o
            .get("purpose")?
            .as_array()?
            .iter()
            .filter_map(|p| p.as_str().map(str::to_string))
            .collect();
        let metadata = o
            .get("metadata")
            .and_then(|m| m.as_object())
            .cloned()
            .unwrap_or_default();
        Some(Self {
            absolute_key_id: o.get("absolute_key_id")?.as_str()?.to_string(),
            short_key_id: o.get("short_key_id")?.as_str()?.to_string(),
            family: o.get("family")?.as_str()?.to_string(),
            algorithm: o.get("algorithm")?.as_str()?.to_string(),
            algorithm_suite: o
                .get("algorithm_suite")
                .and_then(|x| x.as_str().map(str::to_string)),
            encoding: o.get("encoding")?.as_str()?.to_string(),
            purpose,
            public_key: o.get("public_key")?.as_str()?.to_string(),
            private_key: match o.get("private_key") {
                Some(Value::Null) | None => None,
                Some(Value::String(s)) => Some(s.clone()),
                _ => return None,
            },
            created_at: o.get("created_at")?.as_str()?.to_string(),
            status: o.get("status")?.as_str()?.to_string(),
            metadata,
        })
    }

    pub fn copy_with(
        &self,
        status: Option<&str>,
        private_key: Option<Option<String>>,
        created_at: Option<&str>,
    ) -> Self {
        Self {
            absolute_key_id: self.absolute_key_id.clone(),
            short_key_id: self.short_key_id.clone(),
            family: self.family.clone(),
            algorithm: self.algorithm.clone(),
            algorithm_suite: self.algorithm_suite.clone(),
            encoding: self.encoding.clone(),
            purpose: self.purpose.clone(),
            public_key: self.public_key.clone(),
            private_key: match private_key {
                Some(v) => v,
                None => self.private_key.clone(),
            },
            created_at: created_at
                .map(str::to_string)
                .unwrap_or_else(|| self.created_at.clone()),
            status: status
                .map(str::to_string)
                .unwrap_or_else(|| self.status.clone()),
            metadata: self.metadata.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VaultMetadata {
    pub created_at: String,
    pub updated_at: String,
}

impl VaultMetadata {
    pub fn to_json(&self) -> Value {
        json!({
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            created_at: o.get("created_at")?.as_str()?.to_string(),
            updated_at: o.get("updated_at")?.as_str()?.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Tombstone {
    pub absolute_key_id: String,
    pub deleted_at: String,
    pub nonce: String,
    pub reason: String,
}

impl Tombstone {
    pub fn to_json(&self) -> Value {
        json!({
            "absolute_key_id": self.absolute_key_id,
            "deleted_at": self.deleted_at,
            "nonce": self.nonce,
            "reason": self.reason,
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            absolute_key_id: o.get("absolute_key_id")?.as_str()?.to_string(),
            deleted_at: o.get("deleted_at")?.as_str()?.to_string(),
            nonce: o.get("nonce")?.as_str()?.to_string(),
            reason: o.get("reason")?.as_str()?.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct VaultPayload {
    pub identity: Identity,
    pub msk: MskState,
    pub keys: Vec<KeyRecord>,
    /// family -> purpose -> absolute_key_id
    pub preferred_keys: Map<String, Value>,
    pub metadata: VaultMetadata,
    pub tombstones: Vec<Tombstone>,
    pub extensions: Vec<Extension>,
    pub critical_extensions: Vec<Extension>,
}

impl VaultPayload {
    pub fn to_json(&self) -> Value {
        json!({
            "identity": self.identity.to_json(),
            "msk": self.msk.to_json(),
            "keys": self.keys.iter().map(KeyRecord::to_json).collect::<Vec<_>>(),
            "preferred_keys": Value::Object(self.preferred_keys.clone()),
            "metadata": self.metadata.to_json(),
            "tombstones": self.tombstones.iter().map(Tombstone::to_json).collect::<Vec<_>>(),
            "extensions": self.extensions.iter().map(Extension::to_json).collect::<Vec<_>>(),
            "critical_extensions": self.critical_extensions.iter().map(Extension::to_json).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let keys = o
            .get("keys")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(KeyRecord::from_json).collect())
            .unwrap_or_default();
        let tombstones = o
            .get("tombstones")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(Tombstone::from_json).collect())
            .unwrap_or_default();
        let preferred_keys = o
            .get("preferred_keys")
            .and_then(|m| m.as_object())
            .cloned()
            .unwrap_or_default();
        let extensions = o
            .get("extensions")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(Extension::from_json).collect())
            .unwrap_or_default();
        let critical_extensions = o
            .get("critical_extensions")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(Extension::from_json).collect())
            .unwrap_or_default();
        Some(Self {
            identity: Identity::from_json(o.get("identity")?)?,
            msk: MskState::from_json(o.get("msk")?)?,
            keys,
            preferred_keys,
            metadata: VaultMetadata::from_json(o.get("metadata")?)?,
            tombstones,
            extensions,
            critical_extensions,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SignedBody {
    pub protocol: String,
    pub protocol_version: String,
    pub operation: String,
    pub identity_id: String,
    pub vault_id: String,
    pub generation: u64,
    pub nonce: String,
    pub timestamp: String,
    pub payload_hash: String,
}

impl SignedBody {
    pub fn to_json(&self) -> Value {
        json!({
            "protocol": self.protocol,
            "protocol_version": self.protocol_version,
            "operation": self.operation,
            "identity_id": self.identity_id,
            "vault_id": self.vault_id,
            "generation": self.generation,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "payload_hash": self.payload_hash,
        })
    }
}

#[derive(Debug, Clone)]
pub struct OperationSignature {
    pub algorithm: String,
    pub msk_id: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct SignedOperation {
    pub body: SignedBody,
    pub payload: Value,
    pub signature: OperationSignature,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct UnlockedVault {
    #[zeroize(skip)]
    pub container: VaultContainer,
    #[zeroize(skip)]
    pub payload: VaultPayload,
    pub vek: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MergeConflict {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct MergeResult {
    pub payload: VaultPayload,
    pub slots: Vec<UnlockSlot>,
    pub conflicts: Vec<MergeConflict>,
}
