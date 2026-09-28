const identityTypes = ['email', 'dns'];
const keyFamilies = ['openpgp', 'smime'];
const forbiddenFamilies = ['pq', 'pqc', 'post-quantum', 'hybrid'];
const algorithmSuites = ['rsa', 'ecc', 'pqc'];
const keyEncodings = ['openpgp-tsk', 'pkcs8', 'pkcs12'];
const keyStatuses = ['active', 'retired', 'revoked', 'compromised'];
const keyPurposes = ['sign', 'encrypt', 'auth'];
const unlockMethods = [
  'password-argon2id',
  'device-wrap-a256gcm',
  'password-oprf-argon2id',
  'recovery-code-oprf-argon2id',
];

/// Methods that need a host POPRF evaluation (profiles/pepper-oprf.md).
const pepperUnlockMethods = [
  'password-oprf-argon2id',
  'recovery-code-oprf-argon2id',
];
const aeadAlgorithms = ['A256GCM'];
const kdfs = ['Argon2id'];
const mskAlgorithms = ['Ed25519', 'mldsa65-ed25519'];
// Content keys may use RFC 9980 OpenPGP / CMS PQC algorithm *strings* on
// family openpgp or smime. Container 1.0 MSKs stay Ed25519. Container 1.1
// may arm mldsa65-ed25519. Families pq/pqc stay forbidden.

const statusSeverity = <String, int>{
  'active': 0,
  'retired': 1,
  'revoked': 2,
  'compromised': 3,
};

bool isForbiddenFamily(String family) => forbiddenFamilies.contains(family);

/// Map a key algorithm string to CKVF `algorithm_suite`.
/// Hybrids (ML-KEM+X25519, ML-DSA+Ed25519) are `pqc`.
String? algorithmSuiteFromAlgorithm(String algorithm) {
  final n = algorithm.toLowerCase();
  if (n.contains('mlkem') ||
      n.contains('mldsa') ||
      n.contains('ml-kem') ||
      n.contains('ml-dsa') ||
      n.contains('slhdsa') ||
      n.contains('hqc') ||
      n.startsWith('pqc-')) {
    return 'pqc';
  }
  if (n.contains('rsa')) return 'rsa';
  if (n.contains('ecdsa') ||
      n.contains('ecdh') ||
      n.contains('ed25519') ||
      n.contains('ed448') ||
      n.contains('x25519') ||
      n.contains('x448') ||
      n.contains('cv25519') ||
      n.contains('cv448') ||
      n == 'ed25519') {
    return 'ecc';
  }
  return null;
}
