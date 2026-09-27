import 'registries.dart';
import 'types.dart';

const readVersions = [ckvfContainerVersion];
const writeVersions = [ckvfContainerVersion];

bool canReadVersion(String version) => readVersions.contains(version);

bool canWriteVersion(String version) => writeVersions.contains(version);

String defaultWriteVersion() => ckvfContainerVersion;

List<String> supportedAlgorithms() => const [
      'Ed25519',
      'Ed448',
      'X25519',
      'X448',
      'NIST-P-256',
      'NIST-P-384',
      'NIST-P-521',
      'RSA-2048',
      'RSA-3072',
      'RSA-4096',
      'ML-KEM-768',
      'ML-DSA-65',
      'SLH-DSA-SHA2-128s',
    ];

List<String> supportedKeyEncodings() => List<String>.from(const [
      'openpgp-tsk',
      'pkcs8',
      'pkcs12',
    ]);

List<String> supportedUnlockMethods() => List<String>.from(unlockMethods);

List<String> supportedOperations() => const [
      'ADD_KEY',
      'RETIRE_KEY',
      'REVOKE_KEY',
      'SET_PREFERRED_KEY',
      'ADD_DEVICE',
      'REMOVE_DEVICE',
      'COMMIT_VAULT_GENERATION',
      'MERGE_VAULT',
      'UPDATE_METADATA',
      'DELETE_PRIVATE_KEY',
      'ESTABLISH_MSK',
      'REPLACE_MSK',
    ];
