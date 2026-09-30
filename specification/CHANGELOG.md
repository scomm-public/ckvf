# Changelog

This changelog records **specification** revisions (community-draft labels), not SDK SemVer. Container `version` is a separate string inside the JSON file; see [SPEC.md](SPEC.md) Section 14.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- Architecture decisions in [docs/adr](../docs/adr): SComm does not host Vault ciphertext; the VEK stays the confidentiality root (no VRK layer); SComm unlock is offline; sync copies immutable generations to user storage; mailbox OTP does not decrypt a vault; device revocation rotates the VEK.
- [profiles/scomm-local-vault.md](profiles/scomm-local-vault.md) and [profiles/untrusted-sync.md](profiles/untrusted-sync.md). SComm writers require an offline VEK slot, reject pepper-only vaults, and sync immutable generations to untrusted storage.
- Extension `std:key-custody` for portable, device-bound, and external private keys.
- [profiles/scomm-key-lifecycle.md](profiles/scomm-key-lifecycle.md). SComm maps CKVF `status` to cryptographic lifecycle only. `delete-on-retire` is not used. Legacy `compromised` projects to `revoked` plus reason `KEY_COMPROMISE`. Sync cannot lower status severity or clear a tombstone.
- Unlock methods `password-oprf-argon2id` and `recovery-code-oprf-argon2id` ([profiles/pepper-oprf.md](profiles/pepper-oprf.md)). A POPRF evaluation by the vault host is mixed into Argon2id, so a stolen container or host database cannot be attacked offline.
- Extension `std:signing-key-retention`: delete a signing private key when it is retired; keep decryption keys.
- Vault host: `POST /v1/vault/open` and `POST /v1/vault/{vault_id}/msk` with grant and MSK proof rules, `POST /v1/pw-oprf/evaluate`, read authorization, a devices and pairing addendum, and `scomm_vault_client` as the reference client.
- Email OTP: rationale for the hosted profile's 64-bit (11-character Base62) codes.

### Changed

- [profiles/vault-host.md](profiles/vault-host.md) is an optional operator profile. SComm does not operate it.
- SPEC.md §9.6 states that retire and revoke do not delete `private_key`, and that `status` is not publication or destruction.
- The vault grant text adds `iss`, `aud`, `kid`, `amr`, and `idp`, matching the Discovery Protocol.
- `vault_id` on the vault host is 16 random bytes in base64url, as in the container.

- A mail signing key is a private key. It stays on the device or inside the encrypted vault. The public directory does not store or return it. Signature checks use the verification public key, fetched by key id.

## [draft-0.1] — 2026-08-17

### Added

- Initial CKVF SComm.AI Draft 0.1.
- Normative data model for outer container version `"1.0"`, unlock slots, encrypted payload, key records, tombstones, extensions, and signed operations.
- AES-256-GCM vault protection with random VEK; Argon2id password wrapping (RFC 9106 second recommended option); Ed25519 MSK operations over RFC 8785 JCS.
- Identity types `email` and `dns` with canonicalization and `identity_id`.
- Key families `openpgp` and `smime` only; PQC as algorithm/suite, not a family.
- Merge semantics without silent last-writer-wins.
- Email-otp and dns-01 profiles; non-normative reference key service; SComm adapter notes.
- Community registries structured for later IANA migration (no IANA request).
- kramdown-rfc SComm.AI Draft rendering under `ietf/`.

### Status

Not an IETF standard. Wire format `"1.0"` is intended for independent implementation experiments.
