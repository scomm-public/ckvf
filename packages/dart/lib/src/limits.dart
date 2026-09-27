class ParserLimits {
  const ParserLimits({
    required this.maxVaultBytes,
    required this.maxPayloadBytes,
    required this.maxJsonNesting,
    required this.maxKeyCount,
    required this.maxKeyBytes,
    required this.maxExtensionBytes,
    required this.maxUnlockSlots,
    required this.maxTombstones,
    required this.maxExtensions,
    required this.maxArgon2MemoryKiB,
    required this.maxArgon2Time,
    required this.maxArgon2Parallelism,
    required this.minArgon2MemoryKiB,
    required this.minArgon2Time,
    required this.minArgon2Parallelism,
    required this.maxIdentityBytes,
  });

  final int maxVaultBytes;
  final int maxPayloadBytes;
  final int maxJsonNesting;
  final int maxKeyCount;
  final int maxKeyBytes;
  final int maxExtensionBytes;
  final int maxUnlockSlots;
  final int maxTombstones;
  final int maxExtensions;
  final int maxArgon2MemoryKiB;
  final int maxArgon2Time;
  final int maxArgon2Parallelism;
  final int minArgon2MemoryKiB;
  final int minArgon2Time;
  final int minArgon2Parallelism;
  final int maxIdentityBytes;
}

const defaultLimits = ParserLimits(
  maxVaultBytes: 16 * 1024 * 1024,
  maxPayloadBytes: 16 * 1024 * 1024,
  maxJsonNesting: 32,
  maxKeyCount: 1024,
  maxKeyBytes: 1024 * 1024,
  maxExtensionBytes: 64 * 1024,
  maxUnlockSlots: 64,
  maxTombstones: 1024,
  maxExtensions: 64,
  maxArgon2MemoryKiB: 1048576,
  maxArgon2Time: 16,
  maxArgon2Parallelism: 16,
  minArgon2MemoryKiB: 16384,
  minArgon2Time: 2,
  minArgon2Parallelism: 1,
  maxIdentityBytes: 2048,
);

class Argon2idParams {
  const Argon2idParams({
    this.alg = 'Argon2id',
    required this.m,
    required this.t,
    required this.p,
    this.keyLength = 32,
  });

  final String alg;
  final int m;
  final int t;
  final int p;
  final int keyLength;
}

const recommendedArgon2id = Argon2idParams(m: 65536, t: 3, p: 4);

/// Floor for `*-oprf-argon2id` slots (profiles/pepper-oprf.md §1).
const pepperMinArgon2id = Argon2idParams(m: 65536, t: 3, p: 1);

/// Legal for tests/CI; still meets SPEC §6.5 minima.
const testArgon2id = Argon2idParams(m: 16384, t: 2, p: 1);
