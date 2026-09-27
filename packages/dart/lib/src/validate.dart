import 'dart:convert';

import 'base64url.dart';
import 'errors.dart';
import 'limits.dart';
import 'registries.dart';
import 'types.dart';
import 'version.dart';

Map<String, dynamic> asJsonMap(Object? raw, String err) {
  if (raw is Map<String, dynamic>) return raw;
  if (raw is Map) return Map<String, dynamic>.from(raw);
  fail('ERR_JSON', err);
}

Object? parseJsonLimited(String text, [ParserLimits limits = defaultLimits]) {
  if (text.length > limits.maxVaultBytes) {
    fail('ERR_PARSER_LIMIT', 'vault JSON too large');
  }
  Object? parsed;
  try {
    parsed = jsonDecode(text);
  } catch (_) {
    fail('ERR_JSON', 'invalid JSON');
  }
  _assertNesting(parsed, 0, limits.maxJsonNesting);
  return parsed;
}

void _assertNesting(Object? value, int depth, int max) {
  if (depth > max) fail('ERR_PARSER_LIMIT', 'JSON nesting');
  if (value is List) {
    for (final v in value) {
      _assertNesting(v, depth + 1, max);
    }
  } else if (value is Map) {
    for (final v in value.values) {
      _assertNesting(v, depth + 1, max);
    }
  }
}

void rejectUnknownKeys(Map<String, dynamic> obj, List<String> allowed) {
  for (final k in obj.keys) {
    if (!allowed.contains(k)) fail('ERR_FORMAT', 'unknown field $k');
  }
}

VaultContainer validateContainerShape(
  Object? raw, [
  ParserLimits limits = defaultLimits,
]) {
  final o = asJsonMap(raw, 'container is not an object');
  rejectUnknownKeys(o, const [
    'format',
    'version',
    'vault_id',
    'generation',
    'previous_generation_hash',
    'generation_hash',
    'crypto',
    'unlock_slots',
    'ciphertext',
    'tag',
    'extensions',
    'critical_extensions',
  ]);
  if (o['format'] != ckvfFormat) fail('ERR_FORMAT', 'format must be CKVF');
  final version = o['version'];
  if (version is! String || !canReadVersion(version)) {
    fail('ERR_VERSION', 'unsupported version ${o['version']}');
  }
  if (o['vault_id'] is! String) fail('ERR_FORMAT', 'vault_id');
  base64urlToBytes(o['vault_id'] as String, 16);
  final generation = o['generation'];
  if (generation is! num || generation != generation.roundToDouble() || generation < 1) {
    fail('ERR_FORMAT', 'generation');
  }
  final gen = generation.toInt();
  if (gen == 1) {
    if (o['previous_generation_hash'] != null) {
      fail('ERR_FORMAT', 'generation 1 previous_generation_hash must be null');
    }
  } else if (o['previous_generation_hash'] is! String) {
    fail('ERR_FORMAT', 'previous_generation_hash');
  } else {
    base64urlToBytes(o['previous_generation_hash'] as String, 32);
  }
  if (o['generation_hash'] is! String) fail('ERR_FORMAT', 'generation_hash');
  base64urlToBytes(o['generation_hash'] as String, 32);
  if (o['crypto'] is! Map) fail('ERR_FORMAT', 'crypto');
  final crypto = Map<String, dynamic>.from(o['crypto'] as Map);
  rejectUnknownKeys(crypto, const ['aead', 'iv']);
  if (crypto['aead'] != 'A256GCM') {
    fail('ERR_NOT_IMPLEMENTED', 'only A256GCM is mandatory in v1.0');
  }
  if (crypto['iv'] is! String) fail('ERR_FORMAT', 'iv');
  base64urlToBytes(crypto['iv'] as String, 12);
  if (o['unlock_slots'] is! List) fail('ERR_FORMAT', 'unlock_slots');
  final rawSlots = o['unlock_slots'] as List;
  if (rawSlots.length > limits.maxUnlockSlots) {
    fail('ERR_PARSER_LIMIT', 'too many unlock slots');
  }
  final slots = rawSlots.map((s) => validateUnlockSlot(s, limits)).toList();
  final ids = <String>{};
  for (final s in slots) {
    if (ids.contains(s.slotId)) fail('ERR_SLOT_ID', 'duplicate slot_id');
    ids.add(s.slotId);
  }
  if (o['ciphertext'] is! String) fail('ERR_FORMAT', 'ciphertext');
  final ct = base64urlToBytes(o['ciphertext'] as String);
  if (ct.length > limits.maxPayloadBytes) {
    fail('ERR_PARSER_LIMIT', 'ciphertext too large');
  }
  if (o['tag'] is! String) fail('ERR_FORMAT', 'tag');
  base64urlToBytes(o['tag'] as String, 16);
  validateExtensions(o['extensions'], false, limits);
  validateExtensions(o['critical_extensions'], true, limits);
  return VaultContainer.fromJson(o);
}

UnlockSlot validateUnlockSlot(
  Object? raw, [
  ParserLimits limits = defaultLimits,
]) {
  final o = asJsonMap(raw, 'unlock slot');
  rejectUnknownKeys(
    o,
    const ['slot_id', 'method', 'created_at', 'kdf', 'oprf', 'wrap'],
  );
  if (o['slot_id'] is! String) fail('ERR_SLOT_ID', 'slot_id');
  base64urlToBytes(o['slot_id'] as String, 16);
  final method = o['method'];
  if (!unlockMethods.contains(method)) {
    fail('ERR_NOT_IMPLEMENTED', 'unlock method $method');
  }
  if (o['created_at'] is! String || !isRfc3339Z(o['created_at'] as String)) {
    fail('ERR_FORMAT', 'created_at');
  }
  final pepper = pepperUnlockMethods.contains(method);
  if (pepper) {
    _validateOprf(o['oprf']);
  } else if (o.containsKey('oprf')) {
    fail('ERR_FORMAT', 'oprf is only allowed on *-oprf-argon2id slots');
  }
  if (method == 'device-wrap-a256gcm' && o.containsKey('kdf')) {
    fail('ERR_KDF', 'device-wrap slots carry no kdf');
  }
  if (method == 'password-argon2id' || pepper) {
    if (o['kdf'] is! Map) fail('ERR_KDF', 'missing kdf');
    final k = Map<String, dynamic>.from(o['kdf'] as Map);
    rejectUnknownKeys(k, const ['alg', 'salt', 'm', 't', 'p', 'key_length']);
    if (k['alg'] != 'Argon2id') fail('ERR_KDF', 'alg');
    if (k['salt'] is! String) fail('ERR_KDF', 'salt');
    final salt = base64urlToBytes(k['salt'] as String);
    if (salt.length < 16) fail('ERR_KDF', 'salt too short');
    if (k['m'] is! num || k['t'] is! num || k['p'] is! num) fail('ERR_KDF');
    if (k['key_length'] != 32) fail('ERR_KDF', 'key_length');
    final m = (k['m'] as num).toInt();
    final t = (k['t'] as num).toInt();
    final p = (k['p'] as num).toInt();
    if (m < limits.minArgon2MemoryKiB ||
        t < limits.minArgon2Time ||
        p < limits.minArgon2Parallelism) {
      fail('ERR_KDF', 'unsafe Argon2id parameters');
    }
    if (m > limits.maxArgon2MemoryKiB ||
        t > limits.maxArgon2Time ||
        p > limits.maxArgon2Parallelism) {
      fail('ERR_KDF', 'Argon2id parameters exceed parser limits');
    }
    if (pepper && (m < pepperMinArgon2id.m || t < pepperMinArgon2id.t)) {
      fail('ERR_KDF', 'pepper slots need m >= 65536 and t >= 3');
    }
  }
  if (o['wrap'] is! Map) fail('ERR_FORMAT', 'wrap');
  final w = Map<String, dynamic>.from(o['wrap'] as Map);
  rejectUnknownKeys(w, const ['alg', 'iv', 'ciphertext', 'tag']);
  if (w['alg'] != 'A256GCM') fail('ERR_NOT_IMPLEMENTED', 'wrap alg');
  if (w['iv'] is! String ||
      w['ciphertext'] is! String ||
      w['tag'] is! String) {
    fail('ERR_FORMAT', 'wrap fields');
  }
  base64urlToBytes(w['iv'] as String, 12);
  base64urlToBytes(w['ciphertext'] as String, 32);
  base64urlToBytes(w['tag'] as String, 16);
  return UnlockSlot.fromJson(o);
}

void _validateOprf(Object? raw) {
  if (raw is! Map) fail('ERR_FORMAT', 'oprf is required');
  final o = Map<String, dynamic>.from(raw);
  rejectUnknownKeys(o, const ['suite', 'mode', 'kid', 'public_key']);
  if (o['suite'] != 'ristretto255-SHA512') {
    fail('ERR_NOT_IMPLEMENTED', 'oprf suite');
  }
  if (o['mode'] != 'poprf') fail('ERR_NOT_IMPLEMENTED', 'oprf mode');
  final kid = o['kid'];
  if (kid is! String || kid.isEmpty || kid.length > 64) {
    fail('ERR_FORMAT', 'oprf kid');
  }
  if (o['public_key'] is! String) fail('ERR_FORMAT', 'oprf public_key');
  base64urlToBytes(o['public_key'] as String, 32);
}

VaultPayload validatePayloadShape(
  Object? raw, [
  ParserLimits limits = defaultLimits,
]) {
  final o = asJsonMap(raw, 'payload is not an object');
  rejectUnknownKeys(o, const [
    'identity',
    'msk',
    'keys',
    'preferred_keys',
    'metadata',
    'tombstones',
    'extensions',
    'critical_extensions',
  ]);
  if (o['keys'] is! List || (o['keys'] as List).length > limits.maxKeyCount) {
    fail('ERR_PARSER_LIMIT', 'keys');
  }
  for (final k in o['keys'] as List) {
    validateKeyRecord(k, limits);
  }
  if (o['tombstones'] is! List ||
      (o['tombstones'] as List).length > limits.maxTombstones) {
    fail('ERR_PARSER_LIMIT', 'tombstones');
  }
  validateExtensions(o['extensions'], false, limits);
  validateExtensions(o['critical_extensions'], true, limits);
  return VaultPayload.fromJson(o);
}

KeyRecord validateKeyRecord(
  Object? raw, [
  ParserLimits limits = defaultLimits,
]) {
  final o = asJsonMap(raw, 'key record');
  rejectUnknownKeys(o, const [
    'absolute_key_id',
    'short_key_id',
    'family',
    'algorithm',
    'algorithm_suite',
    'encoding',
    'purpose',
    'public_key',
    'private_key',
    'created_at',
    'status',
    'metadata',
  ]);
  final family = o['family'];
  if (family is! String || isForbiddenFamily(family)) {
    fail('ERR_FAMILY', '$family');
  }
  if (!keyFamilies.contains(family)) fail('ERR_FAMILY', family);
  final encoding = o['encoding'];
  if (encoding is! String || !keyEncodings.contains(encoding)) {
    fail('ERR_ENCODING', '$encoding');
  }
  if (family == 'openpgp' && encoding != 'openpgp-tsk') {
    fail('ERR_ENCODING', 'openpgp requires openpgp-tsk');
  }
  if (family == 'smime' && encoding == 'openpgp-tsk') {
    fail('ERR_ENCODING', 'smime cannot use openpgp-tsk');
  }
  final suite = o['algorithm_suite'];
  if (suite != null) {
    if (suite is! String || !algorithmSuites.contains(suite)) {
      fail('ERR_FORMAT', 'algorithm_suite');
    }
  }
  if (o['purpose'] is! List || (o['purpose'] as List).isEmpty) {
    fail('ERR_FORMAT', 'purpose');
  }
  final seen = <String>{};
  for (final p in o['purpose'] as List) {
    if (!keyPurposes.contains(p)) fail('ERR_FORMAT', 'purpose');
    if (!seen.add(p as String)) fail('ERR_FORMAT', 'duplicate purpose');
  }
  final status = o['status'];
  if (status is! String || !keyStatuses.contains(status)) fail('ERR_STATUS');
  if (o['public_key'] is! String) fail('ERR_ENCODING', 'public_key');
  final pub = base64urlToBytes(o['public_key'] as String);
  if (pub.length > limits.maxKeyBytes) fail('ERR_PARSER_LIMIT', 'public_key');
  if (o['private_key'] != null) {
    if (o['private_key'] is! String) fail('ERR_ENCODING', 'private_key');
    final priv = base64urlToBytes(o['private_key'] as String);
    if (priv.length > limits.maxKeyBytes) {
      fail('ERR_PARSER_LIMIT', 'private_key');
    }
  }
  final shortId = o['short_key_id'];
  if (shortId is! String ||
      !RegExp(r'^[0-9A-F]{4}-[0-9A-F]{4}$').hasMatch(shortId)) {
    fail('ERR_SHORT_KEY_ID');
  }
  if (o['metadata'] != null) {
    if (o['metadata'] is! Map ||
        (o['metadata'] as Map).isNotEmpty) {
      fail('ERR_FORMAT', 'unregistered key metadata; use extensions');
    }
  }
  return KeyRecord.fromJson(o);
}

List<Extension> validateExtensions(
  Object? raw,
  bool critical,
  ParserLimits limits,
) {
  if (raw is! List) fail('ERR_EXTENSION', 'extensions must be an array');
  if (raw.length > limits.maxExtensions) {
    fail('ERR_PARSER_LIMIT', 'too many extensions');
  }
  return raw.map((e) {
    final o = asJsonMap(e, 'extension');
    rejectUnknownKeys(o, const ['id', 'critical', 'data']);
    final id = o['id'];
    if (id is! String ||
        !RegExp(r'^(std|exp|priv):[a-z0-9][a-z0-9._-]*$').hasMatch(id)) {
      fail('ERR_EXTENSION', 'id');
    }
    if (o['critical'] != critical) fail('ERR_EXTENSION', 'critical flag mismatch');
    if (!o.containsKey('data')) fail('ERR_EXTENSION', 'data required');
    final encoded = jsonEncode(o['data']);
    if (encoded.length > limits.maxExtensionBytes) {
      fail('ERR_PARSER_LIMIT', 'extension too large');
    }
    if (critical) {
      fail('ERR_CRITICAL_EXTENSION', 'unknown critical extension $id');
    }
    return Extension.fromJson(o);
  }).toList();
}

bool isRfc3339Z(String s) {
  return RegExp(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$').hasMatch(s);
}
