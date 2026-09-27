//! Deterministic merge of unlocked vault payloads and unlock slots.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::aad::slot_fingerprint;
use crate::errors::{fail, fail_msg, CkvfError};
use crate::registries::status_severity;
use crate::types::{
    Extension, KeyRecord, MergeConflict, MergeResult, MskHistoryEntry, Tombstone, UnlockSlot,
    VaultMetadata, VaultPayload, MskState,
};
use serde_json::{Map, Value};

pub fn merge_payloads(
    a: &VaultPayload,
    b: &VaultPayload,
    slots_a: &[UnlockSlot],
    slots_b: &[UnlockSlot],
    generation_a: u64,
    generation_b: u64,
) -> Result<MergeResult, CkvfError> {
    if a.identity.identity_id != b.identity.identity_id {
        return fail("ERR_IDENTITY_MISMATCH");
    }
    if a.identity.r#type != b.identity.r#type || a.identity.value != b.identity.value {
        return fail("ERR_IDENTITY_MISMATCH");
    }
    let mut conflicts = Vec::new();
    if a.msk.current.msk_id != b.msk.current.msk_id {
        return fail_msg("ERR_MERGE_MSK", "current MSK mismatch is a hard conflict");
    }
    let history = union_history(&a.msk.history, &b.msk.history);
    let keys = merge_keys(&a.keys, &b.keys, &a.tombstones, &b.tombstones, &mut conflicts);
    let preferred = merge_preferred(&a.preferred_keys, &b.preferred_keys, &keys, &mut conflicts);
    let tombstones = union_tombstones(&a.tombstones, &b.tombstones);
    let slots = merge_slots(
        slots_a,
        slots_b,
        &mut conflicts,
        generation_a,
        generation_b,
    )?;
    let created = if a.metadata.created_at <= b.metadata.created_at {
        a.metadata.created_at.clone()
    } else {
        b.metadata.created_at.clone()
    };
    let updated = if a.metadata.updated_at >= b.metadata.updated_at {
        a.metadata.updated_at.clone()
    } else {
        b.metadata.updated_at.clone()
    };
    let payload = VaultPayload {
        identity: a.identity.clone(),
        msk: MskState {
            current: a.msk.current.clone(),
            history,
        },
        keys,
        preferred_keys: preferred,
        metadata: VaultMetadata {
            created_at: created,
            updated_at: updated,
        },
        tombstones,
        extensions: union_extensions(&a.extensions, &b.extensions, &mut conflicts),
        critical_extensions: union_extensions(
            &a.critical_extensions,
            &b.critical_extensions,
            &mut conflicts,
        ),
    };
    if !payload.critical_extensions.is_empty() {
        return fail_msg(
            "ERR_CRITICAL_EXTENSION",
            "unknown critical extension during merge",
        );
    }
    Ok(MergeResult {
        payload,
        slots,
        conflicts,
    })
}

fn merge_keys(
    a: &[KeyRecord],
    b: &[KeyRecord],
    tombs_a: &[Tombstone],
    tombs_b: &[Tombstone],
    conflicts: &mut Vec<MergeConflict>,
) -> Vec<KeyRecord> {
    let mut map: BTreeMap<String, KeyRecord> = BTreeMap::new();
    for k in a {
        map.insert(k.absolute_key_id.clone(), k.copy_with(None, None, None));
    }
    for k in b {
        let existing = match map.get(&k.absolute_key_id) {
            Some(e) => e.clone(),
            None => {
                map.insert(k.absolute_key_id.clone(), k.copy_with(None, None, None));
                continue;
            }
        };
        let sev_a = status_severity(&existing.status);
        let sev_b = status_severity(&k.status);
        let status = if sev_a >= sev_b {
            existing.status.clone()
        } else {
            k.status.clone()
        };
        let tomb_a = tombstone_for(tombs_a, &k.absolute_key_id);
        let tomb_b = tombstone_for(tombs_b, &k.absolute_key_id);
        let mut clear = false;
        let mut private_key = existing.private_key.clone().or_else(|| k.private_key.clone());
        if let (Some(ta), Some(tb)) = (tomb_a, tomb_b) {
            if ta.nonce == tb.nonce {
                clear = true;
                private_key = None;
            }
        } else if (tomb_a.is_some() && tomb_b.is_none() && k.private_key.is_some())
            || (tomb_b.is_some() && tomb_a.is_none() && existing.private_key.is_some())
        {
            conflicts.push(MergeConflict {
                code: "ERR_MERGE_PRIVATE_KEY".into(),
                message: format!("destructive delete conflict for {}", k.absolute_key_id),
            });
            private_key = existing.private_key.clone().or_else(|| k.private_key.clone());
        }
        let created = if existing.created_at <= k.created_at {
            existing.created_at.clone()
        } else {
            k.created_at.clone()
        };
        map.insert(
            k.absolute_key_id.clone(),
            existing.copy_with(
                Some(&status),
                Some(if clear { None } else { private_key }),
                Some(&created),
            ),
        );
    }
    map.into_values().collect()
}

fn merge_preferred(
    a: &Map<String, Value>,
    b: &Map<String, Value>,
    keys: &[KeyRecord],
    conflicts: &mut Vec<MergeConflict>,
) -> Map<String, Value> {
    let mut out = Map::new();
    let mut families: HashSet<String> = HashSet::new();
    families.extend(a.keys().cloned());
    families.extend(b.keys().cloned());
    for family in families {
        let pa = a.get(&family).and_then(|v| v.as_object());
        let pb = b.get(&family).and_then(|v| v.as_object());
        let mut purposes: HashSet<String> = HashSet::new();
        if let Some(m) = pa {
            purposes.extend(m.keys().cloned());
        }
        if let Some(m) = pb {
            purposes.extend(m.keys().cloned());
        }
        let mut family_map = Map::new();
        for purpose in purposes {
            let va = pa.and_then(|m| m.get(&purpose)).and_then(|v| v.as_str());
            let vb = pb.and_then(|m| m.get(&purpose)).and_then(|v| v.as_str());
            if let Some(chosen) = pick_preferred(va, vb, keys, conflicts, &family, &purpose) {
                family_map.insert(purpose, Value::String(chosen));
            }
        }
        if !family_map.is_empty() {
            out.insert(family, Value::Object(family_map));
        }
    }
    out
}

fn pick_preferred(
    va: Option<&str>,
    vb: Option<&str>,
    keys: &[KeyRecord],
    conflicts: &mut Vec<MergeConflict>,
    family: &str,
    purpose: &str,
) -> Option<String> {
    let valid = |id: Option<&str>| {
        id.map(|i| keys.iter().any(|k| k.absolute_key_id == i))
            .unwrap_or(false)
    };
    if let (Some(a), Some(b)) = (va, vb) {
        if a != b {
            conflicts.push(MergeConflict {
                code: "ERR_MERGE_PREFERRED_KEY".into(),
                message: format!("{family}/{purpose}"),
            });
            return None;
        }
    }
    let id = va.or(vb)?;
    if valid(Some(id)) {
        Some(id.to_string())
    } else {
        None
    }
}

fn merge_slots(
    a: &[UnlockSlot],
    b: &[UnlockSlot],
    conflicts: &mut Vec<MergeConflict>,
    generation_a: u64,
    generation_b: u64,
) -> Result<Vec<UnlockSlot>, CkvfError> {
    let mut map: HashMap<String, UnlockSlot> = HashMap::new();
    for s in a {
        map.insert(s.slot_id.clone(), s.clone());
    }
    for s in b {
        if let Some(existing) = map.get(&s.slot_id) {
            if slot_fingerprint(existing)? == slot_fingerprint(s)? {
                continue;
            }
            if is_kid_rewrap(existing, s) && generation_a != generation_b {
                if generation_b > generation_a {
                    map.insert(s.slot_id.clone(), s.clone());
                }
                continue;
            }
            conflicts.push(MergeConflict {
                code: "ERR_MERGE_SLOT".into(),
                message: s.slot_id.clone(),
            });
            return fail_msg("ERR_MERGE_SLOT", format!("slot {} differs", s.slot_id));
        } else {
            map.insert(s.slot_id.clone(), s.clone());
        }
    }
    Ok(map.into_values().collect())
}

fn is_kid_rewrap(x: &UnlockSlot, y: &UnlockSlot) -> bool {
    x.method == y.method
        && x.oprf.is_some()
        && y.oprf.is_some()
        && x.oprf.as_ref().unwrap().kid != y.oprf.as_ref().unwrap().kid
}

fn tombstone_for<'a>(tombs: &'a [Tombstone], id: &str) -> Option<&'a Tombstone> {
    tombs.iter().find(|t| t.absolute_key_id == id)
}

fn union_history(a: &[MskHistoryEntry], b: &[MskHistoryEntry]) -> Vec<MskHistoryEntry> {
    let mut map = HashMap::new();
    for h in a.iter().chain(b.iter()) {
        map.insert(h.msk_id.clone(), h.clone());
    }
    map.into_values().collect()
}

fn union_tombstones(a: &[Tombstone], b: &[Tombstone]) -> Vec<Tombstone> {
    let mut map = HashMap::new();
    for t in a.iter().chain(b.iter()) {
        map.insert(format!("{}:{}", t.absolute_key_id, t.nonce), t.clone());
    }
    map.into_values().collect()
}

fn union_extensions(
    a: &[Extension],
    b: &[Extension],
    conflicts: &mut Vec<MergeConflict>,
) -> Vec<Extension> {
    let mut map: HashMap<String, Extension> = HashMap::new();
    for e in a.iter().chain(b.iter()) {
        if let Some(existing) = map.get(&e.id) {
            if existing.data.to_string() != e.data.to_string() {
                conflicts.push(MergeConflict {
                    code: "ERR_EXTENSION".into(),
                    message: format!("extension data conflict {}", e.id),
                });
                continue;
            }
        }
        map.insert(e.id.clone(), e.clone());
    }
    map.into_values().collect()
}
