export const IDENTITY_TYPES = ["email", "dns"] as const;
export const KEY_FAMILIES = ["openpgp", "smime"] as const;
export const FORBIDDEN_FAMILIES = ["pq", "pqc", "post-quantum", "hybrid"] as const;
/** Primitive class inside a family. Not a CKVF family. */
export const ALGORITHM_SUITES = ["rsa", "ecc", "pqc"] as const;
export const KEY_ENCODINGS = ["openpgp-tsk", "pkcs8", "pkcs12"] as const;
export const KEY_STATUSES = ["active", "retired", "revoked", "compromised"] as const;
export const KEY_PURPOSES = ["sign", "encrypt", "auth"] as const;
export const UNLOCK_METHODS = ["password-argon2id", "device-wrap-a256gcm"] as const;
export const AEAD_ALGORITHMS = ["A256GCM"] as const;
export const KDFS = ["Argon2id"] as const;
export const MSK_ALGORITHMS = ["Ed25519"] as const;

export const STATUS_SEVERITY: Record<string, number> = {
  active: 0,
  retired: 1,
  revoked: 2,
  compromised: 3,
};

export function isForbiddenFamily(family: string): boolean {
  return (FORBIDDEN_FAMILIES as readonly string[]).includes(family);
}

/**
 * Map a key algorithm string to CKVF `algorithm_suite`.
 * Hybrids (ML-KEM+X25519, ML-DSA+Ed25519) are `pqc`.
 */
export function algorithmSuiteFromAlgorithm(algorithm: string): "rsa" | "ecc" | "pqc" | null {
  const n = algorithm.toLowerCase();
  if (
    n.includes("mlkem") ||
    n.includes("mldsa") ||
    n.includes("ml-kem") ||
    n.includes("ml-dsa") ||
    n.includes("slhdsa") ||
    n.includes("slh-dsa") ||
    n.includes("hqc") ||
    n.startsWith("pqc-")
  ) {
    return "pqc";
  }
  if (n.includes("rsa")) return "rsa";
  if (
    n.includes("ecdsa") ||
    n.includes("ecdh") ||
    n.includes("ed25519") ||
    n.includes("ed448") ||
    n.includes("x25519") ||
    n.includes("x448") ||
    n.includes("cv25519") ||
    n.includes("cv448") ||
    n === "ed25519"
  ) {
    return "ecc";
  }
  return null;
}
