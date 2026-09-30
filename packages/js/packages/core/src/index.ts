export { CkvfError, CKVF_ERROR_CODES } from "./errors.js";
export type { CkvfErrorCode } from "./errors.js";
export { DEFAULT_LIMITS, RECOMMENDED_ARGON2ID, TEST_ARGON2ID } from "./limits.js";
export type { ParserLimits } from "./limits.js";
export type { CkvfCrypto } from "./crypto-provider.js";
export { constantTimeEqual } from "./crypto-provider.js";
export { jcs, jcsBytes, utf8Encode, utf8Decode } from "./jcs.js";
export { bytesToBase64url, base64urlToBytes } from "./base64url.js";
export { canonicalizeEmail, canonicalizeDns, identityId, makeIdentity, assertIdentity } from "./identity.js";
export { absoluteKeyId, shortKeyId, shortKeyIdFromDigest, keyIds, canonicalPublicKeyBytes } from "./keyid.js";
export { aadObject, vaultAad, wrapAad, containerWithoutGenerationHash } from "./aad.js";
export { computeGenerationHash, assertGenerationHash, detectStaleGeneration, detectGenerationConflict } from "./generation.js";
export {
  canReadVersion,
  canWriteVersion,
  defaultWriteVersion,
  supportedAlgorithms,
  supportedKeyEncodings,
  supportedUnlockMethods,
  supportedOperations,
  READ_VERSIONS,
  WRITE_VERSIONS,
} from "./version.js";
export * from "./types.js";
export { constructOperation, verifyOperation, applyOperation } from "./operations.js";
export { mergePayloads } from "./merge.js";
export { parseJsonLimited, validateContainerShape, validatePayloadShape, validateKeyRecord } from "./validate.js";
export { KEY_CUSTODY_EXTENSION_ID } from "./custody.js";
export {
  createVault,
  openVault,
  lockVault,
  inspectPublicMetadata,
  importPrivateKey,
  exportPrivateKey,
  getKey,
  findKeysByShortId,
  retireKey,
  changePassword,
  addUnlockSlot,
  removeUnlockSlot,
  mergeVaults,
  replaceMsk,
  serializeContainer,
  addTestOpenPgpKey,
  addTestPkcs8Key,
} from "./vault.js";
export { buildOpenPgpEd25519Tsk, buildOpenPgpEd25519Public, canonicalOpenPgpPublicKey } from "./openpgp.js";
export { buildPkcs8Ed25519, buildSpkiEd25519 } from "./pkcs8.js";
export { IDENTITY_TYPES, KEY_FAMILIES, FORBIDDEN_FAMILIES, ALGORITHM_SUITES, STATUS_SEVERITY, algorithmSuiteFromAlgorithm } from "./registries.js";
export { SPEC_LABEL } from "./types.js";
