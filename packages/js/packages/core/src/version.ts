import {
  CKVF_CONTAINER_VERSION,
  CKVF_FORMAT,
  CKVF_PROTOCOL,
  CKVF_PROTOCOL_VERSION,
} from "./types.js";

export const READ_VERSIONS = [CKVF_CONTAINER_VERSION] as const;
export const WRITE_VERSIONS = [CKVF_CONTAINER_VERSION] as const;

export function canReadVersion(version: string): boolean {
  return (READ_VERSIONS as readonly string[]).includes(version);
}

export function canWriteVersion(version: string): boolean {
  return (WRITE_VERSIONS as readonly string[]).includes(version);
}

export function defaultWriteVersion(): string {
  return CKVF_CONTAINER_VERSION;
}

export function supportedAlgorithms(): string[] {
  return [
    "Ed25519",
    "Ed448",
    "X25519",
    "X448",
    "NIST-P-256",
    "NIST-P-384",
    "NIST-P-521",
    "RSA-2048",
    "RSA-3072",
    "RSA-4096",
    "ML-KEM-768",
    "ML-DSA-65",
    "SLH-DSA-SHA2-128s",
    "ML-DSA-65+Ed25519",
    "ML-DSA-87+Ed448",
    "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-256s",
    "ML-KEM-768+X25519",
    "ML-KEM-1024+X448",
  ];
}

export function supportedKeyEncodings(): string[] {
  return ["openpgp-tsk", "pkcs8", "pkcs12"];
}

export function supportedUnlockMethods(): string[] {
  return ["password-argon2id", "device-wrap-a256gcm"];
}

export function supportedOperations(): string[] {
  return [
    "ADD_KEY",
    "RETIRE_KEY",
    "REVOKE_KEY",
    "SET_PREFERRED_KEY",
    "ADD_DEVICE",
    "REMOVE_DEVICE",
    "COMMIT_VAULT_GENERATION",
    "MERGE_VAULT",
    "UPDATE_METADATA",
    "DELETE_PRIVATE_KEY",
    "ESTABLISH_MSK",
    "REPLACE_MSK",
  ];
}

export { CKVF_FORMAT, CKVF_CONTAINER_VERSION, CKVF_PROTOCOL, CKVF_PROTOCOL_VERSION };
