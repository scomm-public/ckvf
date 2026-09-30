import { fail } from "./errors.js";
import { STATUS_SEVERITY } from "./registries.js";
import type {
  KeyRecord,
  MergeConflict,
  MergeResult,
  MskHistoryEntry,
  PreferredKeys,
  Tombstone,
  UnlockSlot,
  VaultPayload,
} from "./types.js";
import { slotFingerprint } from "./aad.js";
import { isUnderstoodCriticalExtension, nonExportableKeyIds } from "./custody.js";

export function mergePayloads(a: VaultPayload, b: VaultPayload, slotsA: UnlockSlot[], slotsB: UnlockSlot[]): MergeResult {
  if (a.identity.identity_id !== b.identity.identity_id) fail("ERR_IDENTITY_MISMATCH");
  if (a.identity.type !== b.identity.type || a.identity.value !== b.identity.value) fail("ERR_IDENTITY_MISMATCH");

  const conflicts: MergeConflict[] = [];

  if (a.msk.current.msk_id !== b.msk.current.msk_id) {
    fail("ERR_MERGE_MSK", "current MSK mismatch is a hard conflict");
  }

  const history = unionHistory(a.msk.history, b.msk.history);
  const bound = nonExportableKeyIds([...a.critical_extensions, ...b.critical_extensions]);
  const keys = mergeKeys(a.keys, b.keys, a.tombstones, b.tombstones, conflicts, bound);
  const preferred = mergePreferred(a.preferred_keys, b.preferred_keys, keys, conflicts);
  const tombstones = unionTombstones(a.tombstones, b.tombstones);
  const slots = mergeSlots(slotsA, slotsB, conflicts);
  const created = a.metadata.created_at <= b.metadata.created_at ? a.metadata.created_at : b.metadata.created_at;

  const payload: VaultPayload = {
    identity: a.identity,
    msk: { current: a.msk.current, history },
    keys,
    preferred_keys: preferred,
    metadata: {
      created_at: created,
      updated_at: a.metadata.updated_at >= b.metadata.updated_at ? a.metadata.updated_at : b.metadata.updated_at,
    },
    tombstones,
    extensions: unionExtensions(a.extensions, b.extensions, conflicts),
    critical_extensions: unionExtensions(a.critical_extensions, b.critical_extensions, conflicts),
  };

  if (payload.critical_extensions.some((e) => !isUnderstoodCriticalExtension(e))) {
    fail("ERR_CRITICAL_EXTENSION", "unknown critical extension during merge");
  }

  return { payload, slots, conflicts };
}

function mergeKeys(
  a: KeyRecord[],
  b: KeyRecord[],
  tombsA: Tombstone[],
  tombsB: Tombstone[],
  conflicts: MergeConflict[],
  nonExportable: Set<string>,
): KeyRecord[] {
  const map = new Map<string, KeyRecord>();
  for (const k of a) map.set(k.absolute_key_id, { ...k });
  for (const k of b) {
    const existing = map.get(k.absolute_key_id);
    if (!existing) {
      map.set(k.absolute_key_id, { ...k });
      continue;
    }
    const sevA = STATUS_SEVERITY[existing.status] ?? 0;
    const sevB = STATUS_SEVERITY[k.status] ?? 0;
    const status = sevA >= sevB ? existing.status : k.status;
    let private_key = existing.private_key ?? k.private_key;
    const tombA = tombsA.find((t) => t.absolute_key_id === k.absolute_key_id);
    const tombB = tombsB.find((t) => t.absolute_key_id === k.absolute_key_id);
    if (tombA && tombB && tombA.nonce === tombB.nonce) {
      private_key = null;
    } else if ((tombA && !tombB && k.private_key) || (tombB && !tombA && existing.private_key)) {
      conflicts.push({
        code: "ERR_MERGE_PRIVATE_KEY",
        message: `destructive delete conflict for ${k.absolute_key_id}`,
      });
      private_key = existing.private_key ?? k.private_key;
    } else {
      private_key = existing.private_key ?? k.private_key;
    }
    map.set(k.absolute_key_id, {
      ...existing,
      status,
      private_key,
      created_at: existing.created_at <= k.created_at ? existing.created_at : k.created_at,
    });
  }
  for (const id of nonExportable) {
    const existing = map.get(id);
    if (existing?.private_key) map.set(id, { ...existing, private_key: null });
  }
  return [...map.values()].sort((x, y) => x.absolute_key_id.localeCompare(y.absolute_key_id));
}

function mergePreferred(
  a: PreferredKeys,
  b: PreferredKeys,
  keys: KeyRecord[],
  conflicts: MergeConflict[],
): PreferredKeys {
  const out: PreferredKeys = {};
  const families = new Set([...Object.keys(a), ...Object.keys(b)]) as Set<keyof PreferredKeys>;
  for (const family of families) {
    const pa = a[family] ?? {};
    const pb = b[family] ?? {};
    const purposes = new Set([...Object.keys(pa), ...Object.keys(pb)]);
    for (const purpose of purposes) {
      const va = pa[purpose as keyof typeof pa];
      const vb = pb[purpose as keyof typeof pb];
      const chosen = pickPreferred(va, vb, keys, conflicts, String(family), String(purpose));
      if (chosen) {
        out[family] ??= {};
        (out[family] as Record<string, string>)[purpose] = chosen;
      }
    }
  }
  return out;
}

function pickPreferred(
  va: string | undefined,
  vb: string | undefined,
  keys: KeyRecord[],
  conflicts: MergeConflict[],
  family: string,
  purpose: string,
): string | undefined {
  const valid = (id?: string) => Boolean(id && keys.some((k) => k.absolute_key_id === id && k.private_key !== undefined));
  if (va && vb && va !== vb) {
    conflicts.push({ code: "ERR_MERGE_PREFERRED_KEY", message: `${family}/${purpose}` });
    return undefined;
  }
  const id = va ?? vb;
  return valid(id) ? id : undefined;
}

function mergeSlots(a: UnlockSlot[], b: UnlockSlot[], conflicts: MergeConflict[]): UnlockSlot[] {
  const map = new Map<string, UnlockSlot>();
  for (const s of a) map.set(s.slot_id, s);
  for (const s of b) {
    const existing = map.get(s.slot_id);
    if (!existing) {
      map.set(s.slot_id, s);
      continue;
    }
    if (slotFingerprint(existing) !== slotFingerprint(s)) {
      conflicts.push({ code: "ERR_MERGE_SLOT", message: s.slot_id });
      fail("ERR_MERGE_SLOT", `slot ${s.slot_id} differs`);
    }
  }
  return [...map.values()];
}

function unionHistory(a: MskHistoryEntry[], b: MskHistoryEntry[]): MskHistoryEntry[] {
  const map = new Map<string, MskHistoryEntry>();
  for (const h of [...a, ...b]) map.set(h.msk_id, h);
  return [...map.values()];
}

function unionTombstones(a: Tombstone[], b: Tombstone[]): Tombstone[] {
  const map = new Map<string, Tombstone>();
  for (const t of [...a, ...b]) map.set(`${t.absolute_key_id}:${t.nonce}`, t);
  return [...map.values()];
}

function unionExtensions(
  a: VaultPayload["extensions"],
  b: VaultPayload["extensions"],
  conflicts: MergeConflict[],
): VaultPayload["extensions"] {
  const map = new Map<string, VaultPayload["extensions"][number]>();
  for (const e of [...a, ...b]) {
    const existing = map.get(e.id);
    if (existing && JSON.stringify(existing.data) !== JSON.stringify(e.data)) {
      conflicts.push({ code: "ERR_EXTENSION", message: `extension data conflict ${e.id}` });
      continue;
    }
    map.set(e.id, e);
  }
  return [...map.values()];
}
