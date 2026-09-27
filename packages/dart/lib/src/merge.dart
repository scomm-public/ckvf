import 'aad.dart';
import 'errors.dart';
import 'registries.dart';
import 'types.dart';

MergeResult mergePayloads(
  VaultPayload a,
  VaultPayload b,
  List<UnlockSlot> slotsA,
  List<UnlockSlot> slotsB, {
  int generationA = 0,
  int generationB = 0,
}) {
  if (a.identity.identityId != b.identity.identityId) {
    fail('ERR_IDENTITY_MISMATCH');
  }
  if (a.identity.type != b.identity.type || a.identity.value != b.identity.value) {
    fail('ERR_IDENTITY_MISMATCH');
  }

  final conflicts = <MergeConflict>[];
  if (a.msk.current.mskId != b.msk.current.mskId) {
    fail('ERR_MERGE_MSK', 'current MSK mismatch is a hard conflict');
  }

  final history = _unionHistory(a.msk.history, b.msk.history);
  final keys = _mergeKeys(a.keys, b.keys, a.tombstones, b.tombstones, conflicts);
  final preferred = _mergePreferred(a.preferredKeys, b.preferredKeys, keys, conflicts);
  final tombstones = _unionTombstones(a.tombstones, b.tombstones);
  final slots = _mergeSlots(
    slotsA,
    slotsB,
    conflicts,
    generationA,
    generationB,
  );
  final created = a.metadata.createdAt.compareTo(b.metadata.createdAt) <= 0
      ? a.metadata.createdAt
      : b.metadata.createdAt;
  final updated = a.metadata.updatedAt.compareTo(b.metadata.updatedAt) >= 0
      ? a.metadata.updatedAt
      : b.metadata.updatedAt;

  final payload = VaultPayload(
    identity: a.identity,
    msk: MskState(current: a.msk.current, history: history),
    keys: keys,
    preferredKeys: preferred,
    metadata: VaultMetadata(createdAt: created, updatedAt: updated),
    tombstones: tombstones,
    extensions: _unionExtensions(a.extensions, b.extensions, conflicts),
    criticalExtensions:
        _unionExtensions(a.criticalExtensions, b.criticalExtensions, conflicts),
  );

  if (payload.criticalExtensions.isNotEmpty) {
    fail('ERR_CRITICAL_EXTENSION', 'unknown critical extension during merge');
  }

  return MergeResult(payload: payload, slots: slots, conflicts: conflicts);
}

List<KeyRecord> _mergeKeys(
  List<KeyRecord> a,
  List<KeyRecord> b,
  List<Tombstone> tombsA,
  List<Tombstone> tombsB,
  List<MergeConflict> conflicts,
) {
  final map = <String, KeyRecord>{};
  for (final k in a) {
    map[k.absoluteKeyId] = k.copyWith();
  }
  for (final k in b) {
    final existing = map[k.absoluteKeyId];
    if (existing == null) {
      map[k.absoluteKeyId] = k.copyWith();
      continue;
    }
    final sevA = statusSeverity[existing.status] ?? 0;
    final sevB = statusSeverity[k.status] ?? 0;
    final status = sevA >= sevB ? existing.status : k.status;
    String? privateKey = existing.privateKey ?? k.privateKey;
    final tombA = _tombstoneFor(tombsA, k.absoluteKeyId);
    final tombB = _tombstoneFor(tombsB, k.absoluteKeyId);
    var clear = false;
    if (tombA != null && tombB != null && tombA.nonce == tombB.nonce) {
      clear = true;
      privateKey = null;
    } else if ((tombA != null && tombB == null && k.privateKey != null) ||
        (tombB != null && tombA == null && existing.privateKey != null)) {
      conflicts.add(
        MergeConflict(
          code: 'ERR_MERGE_PRIVATE_KEY',
          message: 'destructive delete conflict for ${k.absoluteKeyId}',
        ),
      );
      privateKey = existing.privateKey ?? k.privateKey;
    } else {
      privateKey = existing.privateKey ?? k.privateKey;
    }
    final created = existing.createdAt.compareTo(k.createdAt) <= 0
        ? existing.createdAt
        : k.createdAt;
    map[k.absoluteKeyId] = existing.copyWith(
      status: status,
      privateKey: privateKey,
      createdAt: created,
      clearPrivateKey: clear,
    );
  }
  final keys = map.values.toList()
    ..sort((x, y) => x.absoluteKeyId.compareTo(y.absoluteKeyId));
  return keys;
}

Map<String, Map<String, String>> _mergePreferred(
  Map<String, Map<String, String>> a,
  Map<String, Map<String, String>> b,
  List<KeyRecord> keys,
  List<MergeConflict> conflicts,
) {
  final out = <String, Map<String, String>>{};
  final families = {...a.keys, ...b.keys};
  for (final family in families) {
    final pa = a[family] ?? const <String, String>{};
    final pb = b[family] ?? const <String, String>{};
    final purposes = {...pa.keys, ...pb.keys};
    for (final purpose in purposes) {
      final chosen = _pickPreferred(
        pa[purpose],
        pb[purpose],
        keys,
        conflicts,
        family,
        purpose,
      );
      if (chosen != null) {
        out.putIfAbsent(family, () => <String, String>{})[purpose] = chosen;
      }
    }
  }
  return out;
}

String? _pickPreferred(
  String? va,
  String? vb,
  List<KeyRecord> keys,
  List<MergeConflict> conflicts,
  String family,
  String purpose,
) {
  bool valid(String? id) =>
      id != null && keys.any((k) => k.absoluteKeyId == id);
  if (va != null && vb != null && va != vb) {
    conflicts.add(
      MergeConflict(code: 'ERR_MERGE_PREFERRED_KEY', message: '$family/$purpose'),
    );
    return null;
  }
  final id = va ?? vb;
  return valid(id) ? id : null;
}

List<UnlockSlot> _mergeSlots(
  List<UnlockSlot> a,
  List<UnlockSlot> b,
  List<MergeConflict> conflicts,
  int generationA,
  int generationB,
) {
  final map = <String, UnlockSlot>{};
  for (final s in a) {
    map[s.slotId] = s;
  }
  for (final s in b) {
    final existing = map[s.slotId];
    if (existing == null) {
      map[s.slotId] = s;
      continue;
    }
    if (slotFingerprint(existing) == slotFingerprint(s)) continue;
    if (_isKidRewrap(existing, s) && generationA != generationB) {
      if (generationB > generationA) map[s.slotId] = s;
      continue;
    }
    conflicts.add(MergeConflict(code: 'ERR_MERGE_SLOT', message: s.slotId));
    fail('ERR_MERGE_SLOT', 'slot ${s.slotId} differs');
  }
  return map.values.toList();
}

/// Same pepper slot rewrapped under another host `kid` (pepper-oprf.md §6).
bool _isKidRewrap(UnlockSlot x, UnlockSlot y) =>
    x.method == y.method &&
    x.oprf != null &&
    y.oprf != null &&
    x.oprf!.kid != y.oprf!.kid;

Tombstone? _tombstoneFor(List<Tombstone> tombs, String id) {
  for (final t in tombs) {
    if (t.absoluteKeyId == id) return t;
  }
  return null;
}

List<MskHistoryEntry> _unionHistory(
  List<MskHistoryEntry> a,
  List<MskHistoryEntry> b,
) {
  final map = <String, MskHistoryEntry>{};
  for (final h in [...a, ...b]) {
    map[h.mskId] = h;
  }
  return map.values.toList();
}

List<Tombstone> _unionTombstones(List<Tombstone> a, List<Tombstone> b) {
  final map = <String, Tombstone>{};
  for (final t in [...a, ...b]) {
    map['${t.absoluteKeyId}:${t.nonce}'] = t;
  }
  return map.values.toList();
}

List<Extension> _unionExtensions(
  List<Extension> a,
  List<Extension> b,
  List<MergeConflict> conflicts,
) {
  final map = <String, Extension>{};
  for (final e in [...a, ...b]) {
    final existing = map[e.id];
    if (existing != null &&
        existing.data.toString() != e.data.toString()) {
      conflicts.add(
        MergeConflict(
          code: 'ERR_EXTENSION',
          message: 'extension data conflict ${e.id}',
        ),
      );
      continue;
    }
    map[e.id] = e;
  }
  return map.values.toList();
}
