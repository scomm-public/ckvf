# Changelog

## Unreleased

- Unlock slots: `password-oprf-argon2id` and `recovery-code-oprf-argon2id` (profiles/pepper-oprf.md) via `addPepperSlot`, `openVaultWithPepper`, `rewrapPepperSlot`, and a caller-supplied `PepperOprf`; `device-wrap-a256gcm` via `addDeviceSlot` / `openVaultWithDeviceKek`. Pepper slots require Argon2id m ≥ 65536 KiB and t ≥ 3.
- `generateRecoveryCode` / `canonicalRecoveryCode` (26 Base32 characters).
- `openVaultWith` (custom unwrap), `commitUnlockSlots`, and `CreateVaultOptions.vaultId`.
- Merge keeps the newer generation's copy of a pepper slot rewrapped under another `kid`.
- Conformance runs `test-vectors/pepper-oprf/`; `tool/pepper_vectors.dart` rebuilds those containers.
- `algorithm_suite` on content keys is `rsa` | `ecc` | `pqc` (or null). Family remains `openpgp` | `smime`; `pq` / `pqc` stay forbidden as families. Hybrids classify as `pqc`.

## 0.1.0

- Initial CKVF SComm.AI Draft 0.1 implementation (container `"1.0"`).
- Parse, validate, create, encrypt, decrypt, merge, and identifiers.
- Software `DartCkvfCrypto` (AES-256-GCM, Argon2id, Ed25519, SHA-256).
- Pinned test-vector set `0.1.0`.
