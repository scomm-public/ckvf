const ckvfFormat = 'CKVF';
const ckvfContainerVersion = '1.0';
const ckvfProtocol = 'CKVF';
const ckvfProtocolVersion = '1.0';
const specLabel = 'draft-0.1';

typedef IdentityType = String;
typedef KeyFamily = String;
typedef KeyEncoding = String;
typedef KeyStatus = String;
typedef KeyPurpose = String;
typedef UnlockMethod = String;

class Extension {
  Extension({required this.id, required this.critical, required this.data});

  final String id;
  final bool critical;
  final Object? data;

  Map<String, dynamic> toJson() => {
        'id': id,
        'critical': critical,
        'data': data,
      };

  factory Extension.fromJson(Map<String, dynamic> json) => Extension(
        id: json['id'] as String,
        critical: json['critical'] as bool,
        data: json['data'],
      );
}

class CryptoParams {
  CryptoParams({required this.aead, required this.iv});

  final String aead;
  final String iv;

  Map<String, dynamic> toJson() => {'aead': aead, 'iv': iv};

  factory CryptoParams.fromJson(Map<String, dynamic> json) => CryptoParams(
        aead: json['aead'] as String,
        iv: json['iv'] as String,
      );
}

class KdfParams {
  KdfParams({
    required this.alg,
    required this.salt,
    required this.m,
    required this.t,
    required this.p,
    required this.keyLength,
  });

  final String alg;
  final String salt;
  final int m;
  final int t;
  final int p;
  final int keyLength;

  Map<String, dynamic> toJson() => {
        'alg': alg,
        'salt': salt,
        'm': m,
        't': t,
        'p': p,
        'key_length': keyLength,
      };

  factory KdfParams.fromJson(Map<String, dynamic> json) => KdfParams(
        alg: json['alg'] as String,
        salt: json['salt'] as String,
        m: (json['m'] as num).toInt(),
        t: (json['t'] as num).toInt(),
        p: (json['p'] as num).toInt(),
        keyLength: (json['key_length'] as num).toInt(),
      );
}

class WrapParams {
  WrapParams({
    required this.alg,
    required this.iv,
    required this.ciphertext,
    required this.tag,
  });

  final String alg;
  final String iv;
  final String ciphertext;
  final String tag;

  Map<String, dynamic> toJson() => {
        'alg': alg,
        'iv': iv,
        'ciphertext': ciphertext,
        'tag': tag,
      };

  factory WrapParams.fromJson(Map<String, dynamic> json) => WrapParams(
        alg: json['alg'] as String,
        iv: json['iv'] as String,
        ciphertext: json['ciphertext'] as String,
        tag: json['tag'] as String,
      );
}

/// Pinned host key of a `*-oprf-argon2id` slot (profiles/pepper-oprf.md).
class OprfParams {
  OprfParams({
    this.suite = 'ristretto255-SHA512',
    this.mode = 'poprf',
    required this.kid,
    required this.publicKey,
  });

  final String suite;
  final String mode;
  final String kid;
  final String publicKey;

  Map<String, dynamic> toJson() => {
        'suite': suite,
        'mode': mode,
        'kid': kid,
        'public_key': publicKey,
      };

  factory OprfParams.fromJson(Map<String, dynamic> json) => OprfParams(
        suite: json['suite'] as String,
        mode: json['mode'] as String,
        kid: json['kid'] as String,
        publicKey: json['public_key'] as String,
      );
}

class UnlockSlot {
  UnlockSlot({
    required this.slotId,
    required this.method,
    required this.createdAt,
    this.kdf,
    this.oprf,
    required this.wrap,
  });

  final String slotId;
  final UnlockMethod method;
  final String createdAt;
  final KdfParams? kdf;
  final OprfParams? oprf;
  final WrapParams wrap;

  Map<String, dynamic> toJson() => {
        'slot_id': slotId,
        'method': method,
        'created_at': createdAt,
        if (kdf != null) 'kdf': kdf!.toJson(),
        if (oprf != null) 'oprf': oprf!.toJson(),
        'wrap': wrap.toJson(),
      };

  factory UnlockSlot.fromJson(Map<String, dynamic> json) => UnlockSlot(
        slotId: json['slot_id'] as String,
        method: json['method'] as String,
        createdAt: json['created_at'] as String,
        kdf: json['kdf'] is Map
            ? KdfParams.fromJson(Map<String, dynamic>.from(json['kdf'] as Map))
            : null,
        oprf: json['oprf'] is Map
            ? OprfParams.fromJson(
                Map<String, dynamic>.from(json['oprf'] as Map))
            : null,
        wrap: WrapParams.fromJson(Map<String, dynamic>.from(json['wrap'] as Map)),
      );
}

class VaultContainer {
  VaultContainer({
    required this.format,
    required this.version,
    required this.vaultId,
    required this.generation,
    required this.previousGenerationHash,
    required this.generationHash,
    required this.crypto,
    required this.unlockSlots,
    required this.ciphertext,
    required this.tag,
    required this.extensions,
    required this.criticalExtensions,
  });

  String format;
  String version;
  String vaultId;
  int generation;
  String? previousGenerationHash;
  String generationHash;
  CryptoParams crypto;
  List<UnlockSlot> unlockSlots;
  String ciphertext;
  String tag;
  List<Extension> extensions;
  List<Extension> criticalExtensions;

  Map<String, dynamic> toJson() => {
        'format': format,
        'version': version,
        'vault_id': vaultId,
        'generation': generation,
        'previous_generation_hash': previousGenerationHash,
        'generation_hash': generationHash,
        'crypto': crypto.toJson(),
        'unlock_slots': unlockSlots.map((s) => s.toJson()).toList(),
        'ciphertext': ciphertext,
        'tag': tag,
        'extensions': extensions.map((e) => e.toJson()).toList(),
        'critical_extensions': criticalExtensions.map((e) => e.toJson()).toList(),
      };

  factory VaultContainer.fromJson(Map<String, dynamic> json) => VaultContainer(
        format: json['format'] as String,
        version: json['version'] as String,
        vaultId: json['vault_id'] as String,
        generation: (json['generation'] as num).toInt(),
        previousGenerationHash: json['previous_generation_hash'] as String?,
        generationHash: json['generation_hash'] as String,
        crypto: CryptoParams.fromJson(
          Map<String, dynamic>.from(json['crypto'] as Map),
        ),
        unlockSlots: (json['unlock_slots'] as List)
            .map((e) => UnlockSlot.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(),
        ciphertext: json['ciphertext'] as String,
        tag: json['tag'] as String,
        extensions: (json['extensions'] as List? ?? const [])
            .map((e) => Extension.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(),
        criticalExtensions: (json['critical_extensions'] as List? ?? const [])
            .map((e) => Extension.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList(),
      );
}

class Identity {
  Identity({
    required this.type,
    required this.value,
    required this.identityId,
  });

  final IdentityType type;
  final String value;
  final String identityId;

  Map<String, dynamic> toJson() => {
        'type': type,
        'value': value,
        'identity_id': identityId,
      };

  factory Identity.fromJson(Map<String, dynamic> json) => Identity(
        type: json['type'] as String,
        value: json['value'] as String,
        identityId: json['identity_id'] as String,
      );
}

class MskCurrent {
  MskCurrent({
    required this.mskId,
    required this.algorithm,
    required this.publicKey,
    required this.privateKey,
    required this.activatedAt,
  });

  final String mskId;
  final String algorithm;
  final String publicKey;
  final String privateKey;
  final String activatedAt;

  Map<String, dynamic> toJson() => {
        'msk_id': mskId,
        'algorithm': algorithm,
        'public_key': publicKey,
        'private_key': privateKey,
        'activated_at': activatedAt,
      };

  factory MskCurrent.fromJson(Map<String, dynamic> json) => MskCurrent(
        mskId: json['msk_id'] as String,
        algorithm: json['algorithm'] as String,
        publicKey: json['public_key'] as String,
        privateKey: json['private_key'] as String,
        activatedAt: json['activated_at'] as String,
      );
}

class MskHistoryEntry {
  MskHistoryEntry({
    required this.mskId,
    required this.algorithm,
    required this.publicKey,
    required this.activatedAt,
    required this.retiredAt,
  });

  final String mskId;
  final String algorithm;
  final String publicKey;
  final String activatedAt;
  final String retiredAt;

  Map<String, dynamic> toJson() => {
        'msk_id': mskId,
        'algorithm': algorithm,
        'public_key': publicKey,
        'activated_at': activatedAt,
        'retired_at': retiredAt,
      };

  factory MskHistoryEntry.fromJson(Map<String, dynamic> json) => MskHistoryEntry(
        mskId: json['msk_id'] as String,
        algorithm: json['algorithm'] as String,
        publicKey: json['public_key'] as String,
        activatedAt: json['activated_at'] as String,
        retiredAt: json['retired_at'] as String,
      );
}

class MskState {
  MskState({required this.current, required this.history});

  final MskCurrent current;
  final List<MskHistoryEntry> history;

  Map<String, dynamic> toJson() => {
        'current': current.toJson(),
        'history': history.map((h) => h.toJson()).toList(),
      };

  factory MskState.fromJson(Map<String, dynamic> json) => MskState(
        current: MskCurrent.fromJson(
          Map<String, dynamic>.from(json['current'] as Map),
        ),
        history: (json['history'] as List? ?? const [])
            .map(
              (e) => MskHistoryEntry.fromJson(Map<String, dynamic>.from(e as Map)),
            )
            .toList(),
      );
}

class KeyRecord {
  KeyRecord({
    required this.absoluteKeyId,
    required this.shortKeyId,
    required this.family,
    required this.algorithm,
    this.algorithmSuite,
    required this.encoding,
    required this.purpose,
    required this.publicKey,
    required this.privateKey,
    required this.createdAt,
    required this.status,
    Map<String, dynamic>? metadata,
  }) : metadata = metadata ?? <String, dynamic>{};

  final String absoluteKeyId;
  final String shortKeyId;
  final KeyFamily family;
  final String algorithm;
  final String? algorithmSuite;
  final KeyEncoding encoding;
  final List<KeyPurpose> purpose;
  final String publicKey;
  final String? privateKey;
  final String createdAt;
  KeyStatus status;
  final Map<String, dynamic> metadata;

  Map<String, dynamic> toJson() => {
        'absolute_key_id': absoluteKeyId,
        'short_key_id': shortKeyId,
        'family': family,
        'algorithm': algorithm,
        'algorithm_suite': algorithmSuite,
        'encoding': encoding,
        'purpose': purpose,
        'public_key': publicKey,
        'private_key': privateKey,
        'created_at': createdAt,
        'status': status,
        'metadata': metadata,
      };

  factory KeyRecord.fromJson(Map<String, dynamic> json) => KeyRecord(
        absoluteKeyId: json['absolute_key_id'] as String,
        shortKeyId: json['short_key_id'] as String,
        family: json['family'] as String,
        algorithm: json['algorithm'] as String,
        algorithmSuite: json['algorithm_suite'] as String?,
        encoding: json['encoding'] as String,
        purpose: (json['purpose'] as List).map((e) => e.toString()).toList(),
        publicKey: json['public_key'] as String,
        privateKey: json['private_key'] as String?,
        createdAt: json['created_at'] as String,
        status: json['status'] as String,
        metadata: json['metadata'] is Map
            ? Map<String, dynamic>.from(json['metadata'] as Map)
            : <String, dynamic>{},
      );

  KeyRecord copyWith({
    KeyStatus? status,
    String? privateKey,
    String? createdAt,
    bool clearPrivateKey = false,
  }) {
    return KeyRecord(
      absoluteKeyId: absoluteKeyId,
      shortKeyId: shortKeyId,
      family: family,
      algorithm: algorithm,
      algorithmSuite: algorithmSuite,
      encoding: encoding,
      purpose: List<String>.from(purpose),
      publicKey: publicKey,
      privateKey: clearPrivateKey ? null : (privateKey ?? this.privateKey),
      createdAt: createdAt ?? this.createdAt,
      status: status ?? this.status,
      metadata: Map<String, dynamic>.from(metadata),
    );
  }
}

class VaultMetadata {
  VaultMetadata({required this.createdAt, required this.updatedAt});

  String createdAt;
  String updatedAt;

  Map<String, dynamic> toJson() => {
        'created_at': createdAt,
        'updated_at': updatedAt,
      };

  factory VaultMetadata.fromJson(Map<String, dynamic> json) => VaultMetadata(
        createdAt: json['created_at'] as String,
        updatedAt: json['updated_at'] as String,
      );
}

class Tombstone {
  Tombstone({
    required this.absoluteKeyId,
    required this.deletedAt,
    required this.nonce,
    required this.reason,
  });

  final String absoluteKeyId;
  final String deletedAt;
  final String nonce;
  final String reason;

  Map<String, dynamic> toJson() => {
        'absolute_key_id': absoluteKeyId,
        'deleted_at': deletedAt,
        'nonce': nonce,
        'reason': reason,
      };

  factory Tombstone.fromJson(Map<String, dynamic> json) => Tombstone(
        absoluteKeyId: json['absolute_key_id'] as String,
        deletedAt: json['deleted_at'] as String,
        nonce: json['nonce'] as String,
        reason: json['reason'] as String,
      );
}

class VaultPayload {
  VaultPayload({
    required this.identity,
    required this.msk,
    required this.keys,
    required this.preferredKeys,
    required this.metadata,
    required this.tombstones,
    required this.extensions,
    required this.criticalExtensions,
  });

  Identity identity;
  MskState msk;
  List<KeyRecord> keys;
  Map<String, Map<String, String>> preferredKeys;
  VaultMetadata metadata;
  List<Tombstone> tombstones;
  List<Extension> extensions;
  List<Extension> criticalExtensions;

  Map<String, dynamic> toJson() => {
        'identity': identity.toJson(),
        'msk': msk.toJson(),
        'keys': keys.map((k) => k.toJson()).toList(),
        'preferred_keys': preferredKeys,
        'metadata': metadata.toJson(),
        'tombstones': tombstones.map((t) => t.toJson()).toList(),
        'extensions': extensions.map((e) => e.toJson()).toList(),
        'critical_extensions': criticalExtensions.map((e) => e.toJson()).toList(),
      };

  factory VaultPayload.fromJson(Map<String, dynamic> json) {
    final preferred = <String, Map<String, String>>{};
    final rawPreferred = json['preferred_keys'];
    if (rawPreferred is Map) {
      for (final entry in rawPreferred.entries) {
        final inner = entry.value;
        if (inner is Map) {
          preferred[entry.key.toString()] = inner.map(
            (k, v) => MapEntry(k.toString(), v.toString()),
          );
        }
      }
    }
    return VaultPayload(
      identity: Identity.fromJson(Map<String, dynamic>.from(json['identity'] as Map)),
      msk: MskState.fromJson(Map<String, dynamic>.from(json['msk'] as Map)),
      keys: (json['keys'] as List? ?? const [])
          .map((e) => KeyRecord.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList(),
      preferredKeys: preferred,
      metadata: VaultMetadata.fromJson(
        Map<String, dynamic>.from(json['metadata'] as Map),
      ),
      tombstones: (json['tombstones'] as List? ?? const [])
          .map((e) => Tombstone.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList(),
      extensions: (json['extensions'] as List? ?? const [])
          .map((e) => Extension.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList(),
      criticalExtensions: (json['critical_extensions'] as List? ?? const [])
          .map((e) => Extension.fromJson(Map<String, dynamic>.from(e as Map)))
          .toList(),
    );
  }
}

class SignedBody {
  SignedBody({
    required this.protocol,
    required this.protocolVersion,
    required this.operation,
    required this.identityId,
    required this.vaultId,
    required this.generation,
    required this.nonce,
    required this.timestamp,
    required this.payloadHash,
  });

  final String protocol;
  final String protocolVersion;
  final String operation;
  final String identityId;
  final String vaultId;
  final int generation;
  final String nonce;
  final String timestamp;
  final String payloadHash;

  Map<String, dynamic> toJson() => {
        'protocol': protocol,
        'protocol_version': protocolVersion,
        'operation': operation,
        'identity_id': identityId,
        'vault_id': vaultId,
        'generation': generation,
        'nonce': nonce,
        'timestamp': timestamp,
        'payload_hash': payloadHash,
      };
}

class OperationSignature {
  OperationSignature({
    required this.algorithm,
    required this.mskId,
    required this.value,
  });

  final String algorithm;
  final String mskId;
  final String value;

  Map<String, dynamic> toJson() => {
        'algorithm': algorithm,
        'msk_id': mskId,
        'value': value,
      };
}

class SignedOperation {
  SignedOperation({
    required this.body,
    required this.payload,
    required this.signature,
  });

  final SignedBody body;
  final Map<String, dynamic> payload;
  final OperationSignature signature;
}

class UnlockedVault {
  UnlockedVault({
    required this.container,
    required this.payload,
    required this.vek,
  });

  VaultContainer container;
  VaultPayload payload;
  List<int> vek;
}

class MergeConflict {
  MergeConflict({required this.code, required this.message});

  final String code;
  final String message;
}

class MergeResult {
  MergeResult({
    required this.payload,
    required this.slots,
    required this.conflicts,
  });

  final VaultPayload payload;
  final List<UnlockSlot> slots;
  final List<MergeConflict> conflicts;
}
