/// Cryptographic Key Vault Format (CKVF) Dart SDK.
///
/// Community Draft 0.1. This library consumes the same specification, schemas,
/// registries, and test-vectors as other SDKs. It MUST NOT silently redefine
/// CKVF behavior, MUST NOT import Discovery HTTP, and MUST NOT rewrite a vault to a
/// newer container version on open.
library;

import 'src/base64url.dart';
import 'src/crypto_provider.dart';
import 'src/errors.dart';
import 'src/generation.dart';
import 'src/identity.dart' as identity_api;
import 'src/keyid.dart' as keyid_api;
import 'src/types.dart';
import 'src/validate.dart';
import 'src/vault.dart' as vault_api;

export 'src/vault.dart' show replaceMskHybrid;
import 'src/version.dart' as version_api;

export 'src/aad.dart';
export 'src/base64url.dart';
export 'src/crypto_provider.dart';
export 'src/errors.dart';
export 'src/generation.dart';
export 'src/identity.dart';
export 'src/jcs.dart';
export 'src/keyid.dart';
export 'src/limits.dart';
export 'src/merge.dart';
export 'src/openpgp.dart';
export 'src/operations.dart';
export 'src/pkcs8.dart';
export 'src/registries.dart';
export 'src/slots.dart';
export 'src/types.dart';
export 'src/validate.dart';
export 'src/vault.dart';
export 'src/version.dart';

/// Capability and codec surface for CKVF container `"1.0"` (Community Draft 0.1).
abstract final class Ckvf {
  static bool canReadVersion(String v) => version_api.canReadVersion(v);

  static bool canWriteVersion(String v) => version_api.canWriteVersion(v);

  static List<String> supportedAlgorithms() => version_api.supportedAlgorithms();

  static List<String> supportedKeyEncodings() =>
      version_api.supportedKeyEncodings();

  static List<String> supportedUnlockMethods() =>
      version_api.supportedUnlockMethods();

  /// Parse outer container JSON without decrypting.
  static VaultContainer parse(String source) {
    return validateContainerShape(parseJsonLimited(source));
  }

  /// Validate container structure, encodings, and `generation_hash` (fail closed).
  static Future<void> validate(
    Object container, {
    required CkvfCrypto crypto,
  }) async {
    final shaped = container is VaultContainer
        ? validateContainerShape(container.toJson())
        : validateContainerShape(container);
    await assertGenerationHash(shaped, crypto);
  }

  /// Create a new vault bound to an Identity and wrap the VEK with [password].
  static Future<UnlockedVault> create({
    required Object identity,
    required String password,
    required CkvfCrypto crypto,
    String? now,
  }) {
    final resolved = crypto;
    late final String type;
    late final String value;
    if (identity is Identity) {
      type = identity.type;
      value = identity.value;
    } else if (identity is Map) {
      type = '${identity['type']}';
      value = '${identity['value']}';
    } else {
      fail('ERR_FORMAT', 'identity');
    }
    return vault_api.createVault(
      vault_api.CreateVaultOptions(
        identityType: type,
        identityValue: value,
        password: password,
        crypto: resolved,
        now: now,
      ),
    );
  }

  /// Encrypt a payload under the VEK (AES-256-GCM). Passwords wrap the VEK only.
  static Future<VaultContainer> encrypt({
    required UnlockedVault unlocked,
    required CkvfCrypto crypto,
  }) {
    return vault_api.lockVault(unlocked, crypto);
  }

  /// Decrypt a container (password). MUST NOT rewrite on open.
  static Future<UnlockedVault> decrypt({
    required Object container,
    required String password,
    required CkvfCrypto crypto,
  }) {
    return vault_api.openVault(
      container,
      password: password,
      crypto: crypto,
    );
  }

  /// Deterministic merge of two unlocked vaults (no last-writer-wins).
  static Future<UnlockedVault> merge(
    UnlockedVault a,
    UnlockedVault b, {
    required CkvfCrypto crypto,
    String? now,
  }) {
    return vault_api.mergeVaults(a, b, crypto, now);
  }

  /// `identity_id` = unpadded base64url(SHA-256(UTF-8 `type:canonicalValue`)).
  static Future<String> identityId({
    required String type,
    required String value,
    required CkvfCrypto crypto,
  }) {
    return identity_api.identityId(type, value, crypto);
  }

  /// `msk_id` from MSK public key bytes as specified.
  static Future<String> mskId(List<int> publicKey, {required CkvfCrypto crypto}) async {
    final digest = await crypto.sha256(publicKey);
    return bytesToBase64url(digest);
  }

  /// `absolute_key_id` = unpadded base64url(SHA-256(canonical public key bytes)).
  static Future<String> absoluteKeyId(
    List<int> canonicalPublicKeyBytes, {
    required CkvfCrypto crypto,
  }) {
    return keyid_api.absoluteKeyId(
      canonicalPublicKeyBytes,
      crypto,
    );
  }

  /// Short Key ID hint (not unique; collisions MUST be tolerated).
  static String shortKeyId(List<int> digest) {
    return keyid_api.shortKeyIdFromDigest(digest);
  }
}
