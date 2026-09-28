import 'dart:convert';
import 'dart:typed_data';

import 'aad.dart';
import 'base64url.dart';
import 'crypto_provider.dart';
import 'errors.dart';
import 'generation.dart';
import 'identity.dart';
import 'jcs.dart';
import 'keyid.dart';
import 'limits.dart';
import 'merge.dart';
import 'openpgp.dart';
import 'pkcs8.dart';
import 'types.dart';
import 'validate.dart';
import 'version.dart';

/// Builds the first generation's unlock slots for a fresh [vaultId] and VEK.
typedef SlotBuilder = Future<List<UnlockSlot>> Function(
  String vaultId,
  List<int> vek,
);

class CreateVaultOptions {
  CreateVaultOptions({
    required this.identityType,
    required this.identityValue,
    this.password,
    required this.crypto,
    this.now,
    this.kdf,
    this.limits,
    this.vaultId,
    this.mskSeed,
    this.slots,
    this.extensions = const [],
  });

  final IdentityType identityType;
  final String identityValue;

  /// Adds a `password-argon2id` slot. Required unless [slots] is set.
  final String? password;
  final CkvfCrypto crypto;
  final String? now;
  final Argon2idParams? kdf;
  final ParserLimits? limits;

  /// 16-byte base64url. Random when null; set only for vectors and tests.
  final String? vaultId;

  /// Existing Ed25519 MSK seed (32 bytes) to establish. Random when null.
  final List<int>? mskSeed;

  /// Additional first-generation slots (device, pepper).
  final SlotBuilder? slots;

  /// Initial payload extensions.
  final List<Extension> extensions;
}

Future<UnlockedVault> createVault(CreateVaultOptions opts) async {
  final crypto = opts.crypto;
  final now = rfc3339(opts.now);
  if (opts.password == null && opts.slots == null) {
    fail('ERR_SLOT_ID', 'a vault needs at least one unlock slot');
  }
  final identity = await makeIdentity(opts.identityType, opts.identityValue, crypto);
  final seed = opts.mskSeed;
  if (seed != null && seed.length != 32) fail('ERR_FORMAT', 'msk seed');
  final msk = seed == null
      ? await crypto.ed25519Generate()
      : (
          publicKey: await crypto.ed25519PublicFromSeed(seed),
          privateKey: Uint8List.fromList(seed),
        );
  final mskId = bytesToBase64url(await crypto.sha256(msk.publicKey));
  final payload = VaultPayload(
    identity: identity,
    msk: MskState(
      current: MskCurrent(
        mskId: mskId,
        algorithm: 'Ed25519',
        publicKey: bytesToBase64url(msk.publicKey),
        privateKey: bytesToBase64url(msk.privateKey),
        activatedAt: now,
      ),
      history: [],
    ),
    keys: [],
    preferredKeys: {},
    metadata: VaultMetadata(createdAt: now, updatedAt: now),
    tombstones: [],
    extensions: List<Extension>.from(opts.extensions),
    criticalExtensions: [],
  );
  final vek = crypto.randomBytes(32);
  final vaultId = opts.vaultId != null
      ? bytesToBase64url(base64urlToBytes(opts.vaultId!, 16))
      : bytesToBase64url(crypto.randomBytes(16));
  final extra = opts.slots == null
      ? const <UnlockSlot>[]
      : await opts.slots!(vaultId, vek);
  final container = await _sealPayload(
    crypto,
    payload,
    vek,
    vaultId: vaultId,
    generation: 1,
    previousGenerationHash: null,
    slots: extra,
    password: opts.password,
    kdf: opts.kdf ?? testArgon2id,
    now: now,
  );
  return UnlockedVault(container: container, payload: payload, vek: vek);
}

Future<UnlockedVault> openVault(
  Object containerOrJson, {
  required String password,
  required CkvfCrypto crypto,
  String? slotId,
  ParserLimits? limits,
}) {
  return openVaultWith(
    containerOrJson,
    crypto: crypto,
    limits: limits,
    unwrap: (container) => _unwrapVek(
      crypto,
      container.vaultId,
      _selectPasswordSlot(container, slotId),
      password,
    ),
  );
}

/// Validates the container, obtains the VEK from [unwrap] (any slot method),
/// and decrypts the payload. MUST NOT rewrite on open.
Future<UnlockedVault> openVaultWith(
  Object containerOrJson, {
  required CkvfCrypto crypto,
  required Future<Uint8List> Function(VaultContainer container) unwrap,
  ParserLimits? limits,
}) async {
  final resolvedLimits = limits ?? defaultLimits;
  final container = containerOrJson is String
      ? validateContainerShape(parseJsonLimited(containerOrJson, resolvedLimits), resolvedLimits)
      : containerOrJson is VaultContainer
          ? validateContainerShape(containerOrJson.toJson(), resolvedLimits)
          : validateContainerShape(containerOrJson, resolvedLimits);
  if (!canReadVersion(container.version)) fail('ERR_VERSION');
  if (container.criticalExtensions.isNotEmpty) fail('ERR_CRITICAL_EXTENSION');
  final expected = await computeGenerationHash(container, crypto);
  if (expected != container.generationHash) fail('ERR_GENERATION_HASH');
  final vek = await unwrap(container);
  late Uint8List plaintext;
  try {
    plaintext = await crypto.aes256gcmDecrypt(
      vek,
      base64urlToBytes(container.crypto.iv, 12),
      base64urlToBytes(container.ciphertext),
      base64urlToBytes(container.tag, 16),
      vaultAad(container),
    );
  } on CkvfException {
    rethrow;
  } catch (_) {
    fail('ERR_AEAD_DECRYPT');
  }
  late Object? json;
  try {
    json = jsonDecode(utf8Decode(plaintext));
  } catch (_) {
    fail('ERR_JSON', 'payload');
  }
  final payload = validatePayloadShape(json, resolvedLimits);
  if (payload.criticalExtensions.isNotEmpty) fail('ERR_CRITICAL_EXTENSION');
  await assertIdentity(payload.identity, crypto);
  return UnlockedVault(container: container, payload: payload, vek: vek);
}

Future<VaultContainer> lockVault(UnlockedVault unlocked, CkvfCrypto crypto) {
  return _reseal(crypto, unlocked.payload, unlocked.vek, unlocked.container);
}

Map<String, dynamic> inspectPublicMetadata(
  Object containerOrJson, [
  ParserLimits limits = defaultLimits,
]) {
  final raw = containerOrJson is String
      ? parseJsonLimited(containerOrJson, limits)
      : containerOrJson is VaultContainer
          ? containerOrJson.toJson()
          : containerOrJson;
  if (raw is! Map) fail('ERR_JSON');
  final o = Map<String, dynamic>.from(raw);
  final crypto = o['crypto'];
  final slots = o['unlock_slots'];
  return {
    'format': o['format'],
    'version': o['version'],
    'vault_id': o['vault_id'],
    'generation': o['generation'],
    'previous_generation_hash': o['previous_generation_hash'],
    'generation_hash': o['generation_hash'],
    'aead': crypto is Map ? crypto['aead'] : null,
    'unlock_methods': slots is List
        ? slots.map((s) {
            final m = Map<String, dynamic>.from(s as Map);
            return {'slot_id': m['slot_id'], 'method': m['method']};
          }).toList()
        : <Map<String, dynamic>>[],
    'extensions': o['extensions'] is List
        ? (o['extensions'] as List)
            .map((e) => Map<String, dynamic>.from(e as Map)['id'])
            .toList()
        : <Object?>[],
    'critical_extensions': o['critical_extensions'] is List
        ? (o['critical_extensions'] as List)
            .map((e) => Map<String, dynamic>.from(e as Map)['id'])
            .toList()
        : <Object?>[],
  };
}

Future<UnlockedVault> importPrivateKey(
  UnlockedVault unlocked, {
  required CkvfCrypto crypto,
  required KeyFamily family,
  required KeyEncoding encoding,
  required String algorithm,
  String? algorithmSuite,
  required List<KeyPurpose> purpose,
  required List<int> privateKey,
  required List<int> publicKey,
  String? createdAt,
  String? now,
}) async {
  final ts = rfc3339(now);
  var publicBytes = Uint8List.fromList(publicKey);
  if (encoding == 'openpgp-tsk') {
    publicBytes = canonicalOpenPgpPublicKey(publicKey, privateKey);
  }
  final ids = await keyIds(publicBytes, crypto);
  final record = KeyRecord(
    absoluteKeyId: ids.absoluteKeyId,
    shortKeyId: ids.shortKeyId,
    family: family,
    algorithm: algorithm,
    algorithmSuite: algorithmSuite,
    encoding: encoding,
    purpose: purpose,
    publicKey: bytesToBase64url(publicBytes),
    privateKey: bytesToBase64url(privateKey),
    createdAt: createdAt ?? ts,
    status: 'active',
  );
  if (unlocked.payload.keys.any((k) => k.absoluteKeyId == record.absoluteKeyId)) {
    fail('ERR_KEY_ID', 'key already present');
  }
  final payload = VaultPayload(
    identity: unlocked.payload.identity,
    msk: unlocked.payload.msk,
    keys: [...unlocked.payload.keys, record],
    preferredKeys: unlocked.payload.preferredKeys,
    metadata: VaultMetadata(
      createdAt: unlocked.payload.metadata.createdAt,
      updatedAt: ts,
    ),
    tombstones: unlocked.payload.tombstones,
    extensions: unlocked.payload.extensions,
    criticalExtensions: unlocked.payload.criticalExtensions,
  );
  final container = await _incrementAndSeal(crypto, payload, unlocked.vek, unlocked.container);
  return UnlockedVault(container: container, payload: payload, vek: unlocked.vek);
}

KeyRecord? getKey(UnlockedVault unlocked, String absoluteKeyId) {
  for (final k in unlocked.payload.keys) {
    if (k.absoluteKeyId == absoluteKeyId) return k;
  }
  return null;
}

List<KeyRecord> findKeysByShortId(UnlockedVault unlocked, String shortId) {
  final needle = shortId.toUpperCase();
  return unlocked.payload.keys.where((k) => k.shortKeyId == needle).toList();
}

Uint8List exportPrivateKey(UnlockedVault unlocked, String absoluteKeyId) {
  final key = getKey(unlocked, absoluteKeyId);
  if (key == null) fail('ERR_KEY_ID', 'not found');
  if (key.privateKey == null) fail('ERR_KEY_ID', 'private key deleted');
  return base64urlToBytes(key.privateKey!);
}

Future<UnlockedVault> retireKey(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  String absoluteKeyId, [
  String? now,
]) async {
  final ts = rfc3339(now);
  if (!unlocked.payload.keys.any((k) => k.absoluteKeyId == absoluteKeyId)) {
    fail('ERR_KEY_ID');
  }
  final payload = VaultPayload(
    identity: unlocked.payload.identity,
    msk: unlocked.payload.msk,
    keys: unlocked.payload.keys
        .map(
          (k) => k.absoluteKeyId == absoluteKeyId ? k.copyWith(status: 'retired') : k,
        )
        .toList(),
    preferredKeys: unlocked.payload.preferredKeys,
    metadata: VaultMetadata(
      createdAt: unlocked.payload.metadata.createdAt,
      updatedAt: ts,
    ),
    tombstones: unlocked.payload.tombstones,
    extensions: unlocked.payload.extensions,
    criticalExtensions: unlocked.payload.criticalExtensions,
  );
  final container = await _incrementAndSeal(crypto, payload, unlocked.vek, unlocked.container);
  return UnlockedVault(container: container, payload: payload, vek: unlocked.vek);
}

VaultPayload _copyPayload(
  VaultPayload p, {
  List<KeyRecord>? keys,
  Map<String, Map<String, String>>? preferredKeys,
  List<Tombstone>? tombstones,
  List<Extension>? extensions,
  required String updatedAt,
}) {
  return VaultPayload(
    identity: p.identity,
    msk: p.msk,
    keys: keys ?? p.keys,
    preferredKeys: preferredKeys ?? p.preferredKeys,
    metadata: VaultMetadata(createdAt: p.metadata.createdAt, updatedAt: updatedAt),
    tombstones: tombstones ?? p.tombstones,
    extensions: extensions ?? p.extensions,
    criticalExtensions: p.criticalExtensions,
  );
}

Future<UnlockedVault> _commitPayload(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  VaultPayload payload,
) async {
  final container =
      await _incrementAndSeal(crypto, payload, unlocked.vek, unlocked.container);
  return UnlockedVault(container: container, payload: payload, vek: unlocked.vek);
}

/// `REVOKE_KEY`: keeps `private_key` (SPEC §9.6).
Future<UnlockedVault> revokeKey(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  String absoluteKeyId, [
  String? now,
]) {
  if (getKey(unlocked, absoluteKeyId) == null) fail('ERR_KEY_ID');
  final ts = rfc3339(now);
  return _commitPayload(
    unlocked,
    crypto,
    _copyPayload(
      unlocked.payload,
      keys: unlocked.payload.keys
          .map((k) => k.absoluteKeyId == absoluteKeyId ? k.copyWith(status: 'revoked') : k)
          .toList(),
      updatedAt: ts,
    ),
  );
}

/// `DELETE_PRIVATE_KEY` (SPEC §4.5): clears `private_key`, keeps the record,
/// appends a tombstone. [reason] is `user-requested`, `compromised-purge`,
/// or `policy`. A deleted key is at least `retired`.
Future<UnlockedVault> deletePrivateKey(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  String absoluteKeyId, {
  String reason = 'policy',
  String? now,
}) {
  if (!const ['user-requested', 'compromised-purge', 'policy'].contains(reason)) {
    fail('ERR_FORMAT', 'tombstone reason');
  }
  if (getKey(unlocked, absoluteKeyId) == null) fail('ERR_KEY_ID');
  final ts = rfc3339(now);
  return _commitPayload(
    unlocked,
    crypto,
    _copyPayload(
      unlocked.payload,
      keys: unlocked.payload.keys.map((k) {
        if (k.absoluteKeyId != absoluteKeyId) return k;
        return k.copyWith(
          status: k.status == 'active' ? 'retired' : k.status,
          clearPrivateKey: true,
        );
      }).toList(),
      tombstones: [
        ...unlocked.payload.tombstones,
        Tombstone(
          absoluteKeyId: absoluteKeyId,
          deletedAt: ts,
          nonce: bytesToBase64url(crypto.randomBytes(16)),
          reason: reason,
        ),
      ],
      updatedAt: ts,
    ),
  );
}

/// `SET_PREFERRED_KEY`. A null [absoluteKeyId] clears the preference.
Future<UnlockedVault> setPreferredKey(
  UnlockedVault unlocked,
  CkvfCrypto crypto, {
  required KeyFamily family,
  required KeyPurpose purpose,
  String? absoluteKeyId,
  String? now,
}) {
  if (absoluteKeyId != null) {
    final key = getKey(unlocked, absoluteKeyId);
    if (key == null) fail('ERR_KEY_ID');
    if (key.family != family || !key.purpose.contains(purpose)) {
      fail('ERR_KEY_ID', 'preferred key family/purpose');
    }
    if (key.status != 'active') fail('ERR_STATUS', 'preferred key must be active');
  }
  final preferred = {
    for (final e in unlocked.payload.preferredKeys.entries)
      e.key: Map<String, String>.from(e.value),
  };
  final byPurpose = preferred.putIfAbsent(family, () => <String, String>{});
  if (absoluteKeyId == null) {
    byPurpose.remove(purpose);
    if (byPurpose.isEmpty) preferred.remove(family);
  } else {
    byPurpose[purpose] = absoluteKeyId;
  }
  return _commitPayload(
    unlocked,
    crypto,
    _copyPayload(unlocked.payload, preferredKeys: preferred, updatedAt: rfc3339(now)),
  );
}

/// `UPDATE_METADATA`: replaces the payload's non-critical extensions.
Future<UnlockedVault> updateExtensions(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  List<Extension> extensions, [
  String? now,
]) {
  if (extensions.any((e) => e.critical)) {
    fail('ERR_CRITICAL_EXTENSION', 'use critical_extensions');
  }
  return _commitPayload(
    unlocked,
    crypto,
    _copyPayload(unlocked.payload, extensions: extensions, updatedAt: rfc3339(now)),
  );
}

Future<UnlockedVault> changePassword(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  String oldPassword,
  String newPassword, {
  String? now,
  Argon2idParams? kdf,
}) async {
  final ts = rfc3339(now);
  final oldSlot = _selectPasswordSlot(unlocked.container);
  await _unwrapVek(crypto, unlocked.container.vaultId, oldSlot, oldPassword);
  final replacement = await _wrapPasswordSlot(
    crypto,
    unlocked.container.vaultId,
    unlocked.vek,
    newPassword,
    ts,
    kdf ?? _slotKdf(oldSlot),
    oldSlot.slotId,
  );
  final slots = unlocked.container.unlockSlots
      .map((s) => s.slotId == oldSlot.slotId ? replacement : s)
      .toList();
  final container = await _commitEnvelopeChange(crypto, unlocked, slots);
  return UnlockedVault(
    container: container,
    payload: unlocked.payload,
    vek: unlocked.vek,
  );
}

Future<UnlockedVault> addUnlockSlot(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  String password, {
  String? now,
  Argon2idParams? kdf,
}) async {
  final ts = rfc3339(now);
  final slot = await _wrapPasswordSlot(
    crypto,
    unlocked.container.vaultId,
    unlocked.vek,
    password,
    ts,
    kdf,
  );
  final container = await _commitEnvelopeChange(
    crypto,
    unlocked,
    [...unlocked.container.unlockSlots, slot],
  );
  return UnlockedVault(
    container: container,
    payload: unlocked.payload,
    vek: unlocked.vek,
  );
}

Future<UnlockedVault> removeUnlockSlot(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  String slotId,
) async {
  if (unlocked.container.unlockSlots.length <= 1) {
    fail('ERR_SLOT_ID', 'cannot remove last slot');
  }
  final slots =
      unlocked.container.unlockSlots.where((s) => s.slotId != slotId).toList();
  if (slots.length == unlocked.container.unlockSlots.length) {
    fail('ERR_SLOT_ID', 'unknown slot');
  }
  final container = await _commitEnvelopeChange(crypto, unlocked, slots);
  return UnlockedVault(
    container: container,
    payload: unlocked.payload,
    vek: unlocked.vek,
  );
}

Future<UnlockedVault> mergeVaults(
  UnlockedVault a,
  UnlockedVault b,
  CkvfCrypto crypto, [
  String? now,
]) async {
  if (a.container.vaultId != b.container.vaultId) fail('ERR_FORMAT', 'vault_id');
  final ts = rfc3339(now);
  final merged = mergePayloads(
    a.payload,
    b.payload,
    a.container.unlockSlots,
    b.container.unlockSlots,
    generationA: a.container.generation,
    generationB: b.container.generation,
  );
  merged.payload.metadata.updatedAt = ts;
  final parentGen = a.container.generation > b.container.generation
      ? a.container.generation
      : b.container.generation;
  final container = await _sealPayload(
    crypto,
    merged.payload,
    a.vek,
    vaultId: a.container.vaultId,
    generation: parentGen + 1,
    previousGenerationHash: a.container.generationHash,
    slots: merged.slots,
  );
  return UnlockedVault(container: container, payload: merged.payload, vek: a.vek);
}

/// Merges [local] into the stored [head] and seals generation `head + 1`
/// chained to `head.generation_hash`, however many generations [local]
/// advanced offline. When the VEKs differ, [local] rotated after it last saw
/// [head]: its slots and VEK win. Conflicts from SPEC §12 are returned.
Future<({UnlockedVault vault, List<MergeConflict> conflicts})> mergeOnto(
  UnlockedVault head,
  UnlockedVault local,
  CkvfCrypto crypto, [
  String? now,
]) async {
  if (head.container.vaultId != local.container.vaultId) {
    fail('ERR_FORMAT', 'vault_id');
  }
  final rotated = !constantTimeEqual(head.vek, local.vek);
  final merged = mergePayloads(
    head.payload,
    local.payload,
    rotated ? local.container.unlockSlots : head.container.unlockSlots,
    local.container.unlockSlots,
    generationA: head.container.generation,
    generationB: local.container.generation,
  );
  merged.payload.metadata.updatedAt = rfc3339(now);
  final vek = rotated ? local.vek : head.vek;
  final container = await _sealPayload(
    crypto,
    merged.payload,
    vek,
    vaultId: head.container.vaultId,
    generation: head.container.generation + 1,
    previousGenerationHash: head.container.generationHash,
    slots: merged.slots,
  );
  return (
    vault: UnlockedVault(container: container, payload: merged.payload, vek: vek),
    conflicts: merged.conflicts,
  );
}

/// Rotates the VEK and commits a generation whose slots come from [slots]
/// (the old VEK cannot open it). Slots that need a secret this caller does
/// not hold must be rebuilt by [slots] or dropped.
Future<UnlockedVault> rotateVek(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  SlotBuilder slots, [
  String? now,
]) async {
  final vek = crypto.randomBytes(32);
  final next = await slots(unlocked.container.vaultId, vek);
  if (next.isEmpty) fail('ERR_SLOT_ID', 'cannot remove last slot');
  final payload = _copyPayload(unlocked.payload, updatedAt: rfc3339(now));
  final container = await _sealPayload(
    crypto,
    payload,
    vek,
    vaultId: unlocked.container.vaultId,
    generation: unlocked.container.generation + 1,
    previousGenerationHash: unlocked.container.generationHash,
    slots: next,
  );
  return UnlockedVault(container: container, payload: payload, vek: vek);
}

Future<UnlockedVault> replaceMsk(
  UnlockedVault unlocked,
  CkvfCrypto crypto, [
  String? now,
]) async {
  final ts = rfc3339(now);
  final next = await crypto.ed25519Generate();
  final mskId = bytesToBase64url(await crypto.sha256(next.publicKey));
  final old = unlocked.payload.msk.current;
  final payload = VaultPayload(
    identity: unlocked.payload.identity,
    msk: MskState(
      current: MskCurrent(
        mskId: mskId,
        algorithm: 'Ed25519',
        publicKey: bytesToBase64url(next.publicKey),
        privateKey: bytesToBase64url(next.privateKey),
        activatedAt: ts,
      ),
      history: [
        ...unlocked.payload.msk.history,
        MskHistoryEntry(
          mskId: old.mskId,
          algorithm: old.algorithm,
          publicKey: old.publicKey,
          activatedAt: old.activatedAt,
          retiredAt: ts,
        ),
      ],
    ),
    keys: unlocked.payload.keys,
    preferredKeys: unlocked.payload.preferredKeys,
    metadata: VaultMetadata(
      createdAt: unlocked.payload.metadata.createdAt,
      updatedAt: ts,
    ),
    tombstones: unlocked.payload.tombstones,
    extensions: unlocked.payload.extensions,
    criticalExtensions: unlocked.payload.criticalExtensions,
  );
  final container = await _incrementAndSeal(crypto, payload, unlocked.vek, unlocked.container);
  return UnlockedVault(container: container, payload: payload, vek: unlocked.vek);
}

/// Arms `mldsa65-ed25519` and seals container `"1.1"`.
///
/// [publicKey] is the 1,984-byte concatenation. Seeds are 32 bytes each.
/// The previous public key is kept in `msk.history`.
Future<UnlockedVault> replaceMskHybrid(
  UnlockedVault unlocked,
  CkvfCrypto crypto, {
  required List<int> publicKey,
  required List<int> mldsaSeed,
  required List<int> edSeed,
  String? now,
}) async {
  if (publicKey.length != 1984 || mldsaSeed.length != 32 || edSeed.length != 32) {
    fail('ERR_FORMAT', 'hybrid msk');
  }
  final ts = rfc3339(now);
  final mskId = bytesToBase64url(await crypto.sha256(publicKey));
  final old = unlocked.payload.msk.current;
  final payload = VaultPayload(
    identity: unlocked.payload.identity,
    msk: MskState(
      current: MskCurrent(
        mskId: mskId,
        algorithm: 'mldsa65-ed25519',
        publicKey: bytesToBase64url(publicKey),
        privateKey: {
          'mldsa65_seed': bytesToBase64url(mldsaSeed),
          'ed25519_seed': bytesToBase64url(edSeed),
        },
        activatedAt: ts,
      ),
      history: [
        ...unlocked.payload.msk.history,
        MskHistoryEntry(
          mskId: old.mskId,
          algorithm: old.algorithm,
          publicKey: old.publicKey,
          activatedAt: old.activatedAt,
          retiredAt: ts,
        ),
      ],
    ),
    keys: unlocked.payload.keys,
    preferredKeys: unlocked.payload.preferredKeys,
    metadata: VaultMetadata(
      createdAt: unlocked.payload.metadata.createdAt,
      updatedAt: ts,
    ),
    tombstones: unlocked.payload.tombstones,
    extensions: unlocked.payload.extensions,
    criticalExtensions: unlocked.payload.criticalExtensions,
  );
  final container = await _incrementAndSeal(
    crypto,
    payload,
    unlocked.vek,
    unlocked.container,
  );
  return UnlockedVault(container: container, payload: payload, vek: unlocked.vek);
}

String serializeContainer(VaultContainer container) => jcs(container.toJson());

Future<UnlockedVault> addTestOpenPgpKey(
  UnlockedVault unlocked,
  CkvfCrypto crypto, [
  String? now,
]) async {
  final ts = rfc3339(now);
  final pair = await crypto.ed25519Generate();
  final created = DateTime.parse(ts).toUtc().millisecondsSinceEpoch ~/ 1000;
  return importPrivateKey(
    unlocked,
    crypto: crypto,
    family: 'openpgp',
    encoding: 'openpgp-tsk',
    algorithm: 'Ed25519',
    purpose: const ['sign', 'encrypt'],
    privateKey: buildOpenPgpEd25519Tsk(pair.privateKey, pair.publicKey, created),
    publicKey: buildOpenPgpEd25519Public(pair.publicKey, created),
    now: ts,
  );
}

Future<UnlockedVault> addTestPkcs8Key(
  UnlockedVault unlocked,
  CkvfCrypto crypto, [
  String? now,
]) async {
  final ts = rfc3339(now);
  final pair = await crypto.ed25519Generate();
  return importPrivateKey(
    unlocked,
    crypto: crypto,
    family: 'smime',
    encoding: 'pkcs8',
    algorithm: 'Ed25519',
    purpose: const ['sign', 'encrypt'],
    privateKey: buildPkcs8Ed25519(pair.privateKey, pair.publicKey),
    publicKey: buildSpkiEd25519(pair.publicKey),
    now: ts,
  );
}

String rfc3339([String? now]) {
  if (now != null) return now;
  return DateTime.now().toUtc().toIso8601String().replaceFirst(RegExp(r'\.\d+Z$'), 'Z');
}

Future<VaultContainer> _sealPayload(
  CkvfCrypto crypto,
  VaultPayload payload,
  List<int> vek, {
  required String vaultId,
  required int generation,
  required String? previousGenerationHash,
  required List<UnlockSlot> slots,
  String? password,
  Argon2idParams? kdf,
  String? now,
  List<int>? iv,
}) async {
  var resolvedSlots = slots;
  if (password != null) {
    final slot = await _wrapPasswordSlot(
      crypto,
      vaultId,
      vek,
      password,
      rfc3339(now),
      kdf,
    );
    resolvedSlots = [slot, ...slots];
  }
  final nonce = iv ?? crypto.randomBytes(12);
  final draft = VaultContainer(
    format: ckvfFormat,
    version: payload.msk.current.algorithm == 'mldsa65-ed25519'
        ? ckvfContainerVersion11
        : ckvfContainerVersion,
    vaultId: vaultId,
    generation: generation,
    previousGenerationHash: previousGenerationHash,
    generationHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    crypto: CryptoParams(aead: 'A256GCM', iv: bytesToBase64url(nonce)),
    unlockSlots: resolvedSlots,
    ciphertext: '',
    tag: 'AAAAAAAAAAAAAAAAAAAAAA',
    extensions: const [],
    criticalExtensions: const [],
  );
  final enc = await crypto.aes256gcmEncrypt(
    vek,
    nonce,
    utf8Encode(jcs(payload.toJson())),
    vaultAad(draft),
  );
  draft.ciphertext = bytesToBase64url(enc.ciphertext);
  draft.tag = bytesToBase64url(enc.tag);
  draft.generationHash = await computeGenerationHash(draft, crypto);
  return draft;
}

Future<VaultContainer> _incrementAndSeal(
  CkvfCrypto crypto,
  VaultPayload payload,
  List<int> vek,
  VaultContainer previous,
) {
  return _sealPayload(
    crypto,
    payload,
    vek,
    vaultId: previous.vaultId,
    generation: previous.generation + 1,
    previousGenerationHash: previous.generationHash,
    slots: previous.unlockSlots,
  );
}

Future<VaultContainer> _reseal(
  CkvfCrypto crypto,
  VaultPayload payload,
  List<int> vek,
  VaultContainer previous,
) {
  return _sealPayload(
    crypto,
    payload,
    vek,
    vaultId: previous.vaultId,
    generation: previous.generation,
    previousGenerationHash: previous.previousGenerationHash,
    slots: previous.unlockSlots,
    iv: base64urlToBytes(previous.crypto.iv, 12),
  );
}

/// Replace the slot set and commit a new generation (same VEK and payload).
Future<UnlockedVault> commitUnlockSlots(
  UnlockedVault unlocked,
  CkvfCrypto crypto,
  List<UnlockSlot> slots,
) async {
  final ids = <String>{};
  for (final s in slots) {
    if (!ids.add(s.slotId)) fail('ERR_SLOT_ID', 'duplicate slot_id');
  }
  if (slots.isEmpty) fail('ERR_SLOT_ID', 'cannot remove last slot');
  final container = await _commitEnvelopeChange(crypto, unlocked, slots);
  return UnlockedVault(
    container: container,
    payload: unlocked.payload,
    vek: unlocked.vek,
  );
}

Future<VaultContainer> _commitEnvelopeChange(
  CkvfCrypto crypto,
  UnlockedVault unlocked,
  List<UnlockSlot> slots,
) {
  return _sealPayload(
    crypto,
    unlocked.payload,
    unlocked.vek,
    vaultId: unlocked.container.vaultId,
    generation: unlocked.container.generation + 1,
    previousGenerationHash: unlocked.container.generationHash,
    slots: slots,
  );
}

/// Reseals the same payload, VEK, and slots as [generation] chained to
/// [previousGenerationHash] (null only for generation 1). Used to restart a
/// local chain on a host that has not stored it.
Future<UnlockedVault> rechain(
  UnlockedVault unlocked,
  CkvfCrypto crypto, {
  required int generation,
  required String? previousGenerationHash,
}) async {
  if (generation < 1 || (generation == 1) != (previousGenerationHash == null)) {
    fail('ERR_FORMAT', 'generation chain');
  }
  final container = await _sealPayload(
    crypto,
    unlocked.payload,
    unlocked.vek,
    vaultId: unlocked.container.vaultId,
    generation: generation,
    previousGenerationHash: previousGenerationHash,
    slots: unlocked.container.unlockSlots,
  );
  return UnlockedVault(container: container, payload: unlocked.payload, vek: unlocked.vek);
}

Future<UnlockSlot> _wrapPasswordSlot(
  CkvfCrypto crypto,
  String vaultId,
  List<int> vek,
  String password,
  String now, [
  Argon2idParams? kdf,
  String? slotId,
]) async {
  final params = kdf ?? testArgon2id;
  final salt = crypto.randomBytes(16);
  final id = slotId ?? bytesToBase64url(crypto.randomBytes(16));
  final kek = await crypto.argon2id(
    password: utf8Encode(password),
    salt: salt,
    m: params.m,
    t: params.t,
    p: params.p,
    keyLength: 32,
  );
  final iv = crypto.randomBytes(12);
  final wrapped = await crypto.aes256gcmEncrypt(
    kek,
    iv,
    vek,
    wrapAad('password-argon2id', id, vaultId),
  );
  return UnlockSlot(
    slotId: id,
    method: 'password-argon2id',
    createdAt: now,
    kdf: KdfParams(
      alg: 'Argon2id',
      salt: bytesToBase64url(salt),
      m: params.m,
      t: params.t,
      p: params.p,
      keyLength: 32,
    ),
    wrap: WrapParams(
      alg: 'A256GCM',
      iv: bytesToBase64url(iv),
      ciphertext: bytesToBase64url(wrapped.ciphertext),
      tag: bytesToBase64url(wrapped.tag),
    ),
  );
}

Future<Uint8List> _unwrapVek(
  CkvfCrypto crypto,
  String vaultId,
  UnlockSlot slot,
  String password,
) async {
  if (slot.method != 'password-argon2id' || slot.kdf == null) {
    fail('ERR_UNLOCK', 'password slot required');
  }
  final kek = await crypto.argon2id(
    password: utf8Encode(password),
    salt: base64urlToBytes(slot.kdf!.salt),
    m: slot.kdf!.m,
    t: slot.kdf!.t,
    p: slot.kdf!.p,
    keyLength: slot.kdf!.keyLength,
  );
  try {
    return await crypto.aes256gcmDecrypt(
      kek,
      base64urlToBytes(slot.wrap.iv, 12),
      base64urlToBytes(slot.wrap.ciphertext, 32),
      base64urlToBytes(slot.wrap.tag, 16),
      wrapAad(slot.method, slot.slotId, vaultId),
    );
  } on CkvfException catch (e) {
    if (e.code == 'ERR_AEAD_DECRYPT') fail('ERR_WRAP_DECRYPT');
    rethrow;
  } catch (_) {
    fail('ERR_WRAP_DECRYPT');
  }
}

UnlockSlot _selectPasswordSlot(VaultContainer container, [String? slotId]) {
  final slots =
      container.unlockSlots.where((s) => s.method == 'password-argon2id').toList();
  if (slots.isEmpty) fail('ERR_UNLOCK', 'no password slot');
  if (slotId != null) {
    for (final s in slots) {
      if (s.slotId == slotId) return s;
    }
    fail('ERR_SLOT_ID');
  }
  return slots.first;
}

Argon2idParams _slotKdf(UnlockSlot slot) {
  final k = slot.kdf;
  if (k == null) return testArgon2id;
  return Argon2idParams(m: k.m, t: k.t, p: k.p, keyLength: k.keyLength);
}
