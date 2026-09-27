import 'dart:typed_data';

import 'package:unorm_dart/unorm_dart.dart' as unorm;

import 'aad.dart';
import 'base64url.dart';
import 'crypto_provider.dart';
import 'errors.dart';
import 'jcs.dart';
import 'limits.dart';
import 'registries.dart';
import 'types.dart';
import 'vault.dart';

const deviceWrapMethod = 'device-wrap-a256gcm';
const passwordOprfMethod = 'password-oprf-argon2id';
const recoveryCodeOprfMethod = 'recovery-code-oprf-argon2id';

/// Host POPRF key a new slot pins (`GET /v1/pw-oprf/keys` on the vault host).
class PepperKey {
  const PepperKey({required this.kid, required this.publicKey});

  final String kid;
  final Uint8List publicKey;
}

/// One POPRF round trip (profiles/pepper-oprf.md §2). Implementations blind
/// [secret], call the host with `{vault_id, slot_id, kid, blind}`, verify the
/// proof against [publicKey], and return the 64-byte Finalize output. This
/// package never talks to the host itself.
abstract interface class PepperOprf {
  Future<Uint8List> finalize({
    required String vaultId,
    required String slotId,
    required String kid,
    required Uint8List publicKey,
    required Uint8List secret,
  });
}

/// UTF-8 of the NFC password, or of the canonical recovery code.
Uint8List pepperSecret(String method, String secret) {
  if (method == recoveryCodeOprfMethod) {
    return utf8Encode(canonicalRecoveryCode(secret));
  }
  if (method == passwordOprfMethod) return utf8Encode(unorm.nfc(secret));
  fail('ERR_UNLOCK', 'not a pepper method');
}

const _base32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/// 26 Base32 characters (130 bits), grouped by five for display.
String generateRecoveryCode(CkvfCrypto crypto) {
  final bytes = crypto.randomBytes(17);
  var bits = 0;
  var acc = 0;
  final out = StringBuffer();
  for (final b in bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5 && out.length < 26) {
      bits -= 5;
      out.write(_base32[(acc >> bits) & 31]);
    }
    acc &= (1 << bits) - 1;
  }
  final code = out.toString();
  final groups = <String>[];
  for (var i = 0; i < code.length; i += 5) {
    groups.add(code.substring(i, i + 5 > code.length ? code.length : i + 5));
  }
  return groups.join('-');
}

/// Removes spaces and hyphens, uppercases, and requires 26 Base32 characters.
String canonicalRecoveryCode(String code) {
  final c = code.replaceAll(RegExp(r'[\s-]'), '').toUpperCase();
  if (!RegExp(r'^[A-Z2-7]{26}$').hasMatch(c)) {
    fail('ERR_UNLOCK', 'recovery code must be 26 Base32 characters');
  }
  return c;
}

Future<Uint8List> _pepperKek(
  CkvfCrypto crypto, {
  required String vaultId,
  required String slotId,
  required String method,
  required String secret,
  required PepperOprf pepper,
  required OprfParams oprf,
  required KdfParams kdf,
}) async {
  final secretBytes = pepperSecret(method, secret);
  final rwd = await pepper.finalize(
    vaultId: vaultId,
    slotId: slotId,
    kid: oprf.kid,
    publicKey: base64urlToBytes(oprf.publicKey, 32),
    secret: secretBytes,
  );
  if (rwd.length != 64) fail('ERR_UNLOCK', 'pepper output must be 64 bytes');
  return crypto.argon2id(
    password: Uint8List.fromList([...rwd, ...secretBytes]),
    salt: base64urlToBytes(kdf.salt),
    m: kdf.m,
    t: kdf.t,
    p: kdf.p,
    keyLength: kdf.keyLength,
  );
}

Future<WrapParams> _wrap(
  CkvfCrypto crypto,
  List<int> kek,
  List<int> vek,
  String method,
  String slotId,
  String vaultId,
) async {
  final iv = crypto.randomBytes(12);
  final wrapped = await crypto.aes256gcmEncrypt(
    kek,
    iv,
    vek,
    wrapAad(method, slotId, vaultId),
  );
  return WrapParams(
    alg: 'A256GCM',
    iv: bytesToBase64url(iv),
    ciphertext: bytesToBase64url(wrapped.ciphertext),
    tag: bytesToBase64url(wrapped.tag),
  );
}

Future<Uint8List> _unwrap(
  CkvfCrypto crypto,
  List<int> kek,
  UnlockSlot slot,
  String vaultId,
) async {
  try {
    return await crypto.aes256gcmDecrypt(
      kek,
      base64urlToBytes(slot.wrap.iv, 12),
      base64urlToBytes(slot.wrap.ciphertext, 32),
      base64urlToBytes(slot.wrap.tag, 16),
      wrapAad(slot.method, slot.slotId, vaultId),
    );
  } catch (_) {
    fail('ERR_WRAP_DECRYPT');
  }
}

UnlockSlot _slotById(
    VaultContainer container, String slotId, List<String> methods) {
  for (final s in container.unlockSlots) {
    if (s.slotId == slotId) {
      if (!methods.contains(s.method)) fail('ERR_UNLOCK', 'slot method');
      return s;
    }
  }
  fail('ERR_SLOT_ID');
}

/// Builds a pepper slot. [slotId] is random unless given (vectors, rewrap).
Future<UnlockSlot> wrapPepperSlot(
  CkvfCrypto crypto, {
  required String vaultId,
  required List<int> vek,
  required String method,
  required String secret,
  required PepperOprf pepper,
  required PepperKey key,
  Argon2idParams kdf = recommendedArgon2id,
  String? slotId,
  String? now,
}) async {
  if (!pepperUnlockMethods.contains(method)) {
    fail('ERR_UNLOCK', 'not a pepper method');
  }
  if (kdf.m < pepperMinArgon2id.m || kdf.t < pepperMinArgon2id.t) {
    fail('ERR_KDF', 'pepper slots need m >= 65536 and t >= 3');
  }
  final id = slotId ?? bytesToBase64url(crypto.randomBytes(16));
  final oprf = OprfParams(
    kid: key.kid,
    publicKey: bytesToBase64url(key.publicKey),
  );
  final kdfParams = KdfParams(
    alg: 'Argon2id',
    salt: bytesToBase64url(crypto.randomBytes(16)),
    m: kdf.m,
    t: kdf.t,
    p: kdf.p,
    keyLength: 32,
  );
  final kek = await _pepperKek(
    crypto,
    vaultId: vaultId,
    slotId: id,
    method: method,
    secret: secret,
    pepper: pepper,
    oprf: oprf,
    kdf: kdfParams,
  );
  return UnlockSlot(
    slotId: id,
    method: method,
    createdAt: rfc3339(now),
    kdf: kdfParams,
    oprf: oprf,
    wrap: await _wrap(crypto, kek, vek, method, id, vaultId),
  );
}

/// Adds a `password-oprf-argon2id` or `recovery-code-oprf-argon2id` slot and
/// commits a generation.
Future<UnlockedVault> addPepperSlot(
  UnlockedVault unlocked,
  CkvfCrypto crypto, {
  required String method,
  required String secret,
  required PepperOprf pepper,
  required PepperKey key,
  Argon2idParams kdf = recommendedArgon2id,
  String? slotId,
  String? now,
}) async {
  final slot = await wrapPepperSlot(
    crypto,
    vaultId: unlocked.container.vaultId,
    vek: unlocked.vek,
    method: method,
    secret: secret,
    pepper: pepper,
    key: key,
    kdf: kdf,
    slotId: slotId,
    now: now,
  );
  return commitUnlockSlots(
    unlocked,
    crypto,
    [...unlocked.container.unlockSlots, slot],
  );
}

/// Opens with a pepper slot. Without [slotId], tries each slot of [method]
/// in container order (one host evaluation per attempt).
Future<UnlockedVault> openVaultWithPepper(
  Object containerOrJson, {
  required String secret,
  required PepperOprf pepper,
  required CkvfCrypto crypto,
  String method = passwordOprfMethod,
  String? slotId,
  ParserLimits? limits,
}) {
  return openVaultWith(
    containerOrJson,
    crypto: crypto,
    limits: limits,
    unwrap: (container) async {
      final candidates = slotId != null
          ? [_slotById(container, slotId, pepperUnlockMethods)]
          : container.unlockSlots.where((s) => s.method == method).toList();
      if (candidates.isEmpty) fail('ERR_UNLOCK', 'no $method slot');
      for (final slot in candidates) {
        final kek = await _pepperKek(
          crypto,
          vaultId: container.vaultId,
          slotId: slot.slotId,
          method: slot.method,
          secret: secret,
          pepper: pepper,
          oprf: slot.oprf!,
          kdf: slot.kdf!,
        );
        try {
          return await _unwrap(crypto, kek, slot, container.vaultId);
        } on CkvfException catch (e) {
          if (e.code != 'ERR_WRAP_DECRYPT' || slot == candidates.last) rethrow;
        }
      }
      fail('ERR_WRAP_DECRYPT');
    },
  );
}

/// After an unlock through a slot pinned to a retired `kid`: rewrap it under
/// [key] (new salt and IV, same `slot_id` and VEK) and commit a generation.
Future<UnlockedVault> rewrapPepperSlot(
  UnlockedVault unlocked,
  CkvfCrypto crypto, {
  required String slotId,
  required String secret,
  required PepperOprf pepper,
  required PepperKey key,
  String? now,
}) async {
  final old = _slotById(unlocked.container, slotId, pepperUnlockMethods);
  final kdf = old.kdf!;
  final replacement = await wrapPepperSlot(
    crypto,
    vaultId: unlocked.container.vaultId,
    vek: unlocked.vek,
    method: old.method,
    secret: secret,
    pepper: pepper,
    key: key,
    kdf: Argon2idParams(m: kdf.m, t: kdf.t, p: kdf.p),
    slotId: slotId,
    now: now,
  );
  return commitUnlockSlots(
    unlocked,
    crypto,
    unlocked.container.unlockSlots
        .map((s) => s.slotId == slotId ? replacement : s)
        .toList(),
  );
}

/// Builds a `device-wrap-a256gcm` slot wrapping [vek] under [kek] (32 bytes
/// from platform secure storage).
Future<UnlockSlot> wrapDeviceSlot(
  CkvfCrypto crypto, {
  required String vaultId,
  required List<int> vek,
  required List<int> kek,
  String? slotId,
  String? now,
}) async {
  if (kek.length != 32) fail('ERR_UNLOCK', 'device KEK must be 32 bytes');
  final id = slotId ?? bytesToBase64url(crypto.randomBytes(16));
  return UnlockSlot(
    slotId: id,
    method: deviceWrapMethod,
    createdAt: rfc3339(now),
    wrap: await _wrap(crypto, kek, vek, deviceWrapMethod, id, vaultId),
  );
}

/// Adds a `device-wrap-a256gcm` slot wrapping the VEK under [kek] (32 bytes
/// from platform secure storage) and commits a generation.
Future<UnlockedVault> addDeviceSlot(
  UnlockedVault unlocked,
  CkvfCrypto crypto, {
  required List<int> kek,
  String? slotId,
  String? now,
}) async {
  final slot = await wrapDeviceSlot(
    crypto,
    vaultId: unlocked.container.vaultId,
    vek: unlocked.vek,
    kek: kek,
    slotId: slotId,
    now: now,
  );
  return commitUnlockSlots(
    unlocked,
    crypto,
    [...unlocked.container.unlockSlots, slot],
  );
}

/// Opens offline with a device slot.
Future<UnlockedVault> openVaultWithDeviceKek(
  Object containerOrJson, {
  required String slotId,
  required List<int> kek,
  required CkvfCrypto crypto,
  ParserLimits? limits,
}) {
  return openVaultWith(
    containerOrJson,
    crypto: crypto,
    limits: limits,
    unwrap: (container) => _unwrap(
      crypto,
      kek,
      _slotById(container, slotId, const [deviceWrapMethod]),
      container.vaultId,
    ),
  );
}
