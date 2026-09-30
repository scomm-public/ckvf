# SComm local vault profile

**Status:** SComm.AI Draft  
**Applies to:** SComm writers and readers of CKVF containers  
**Container version:** `"1.0"` (and `"1.1"` only for the already registered hybrid MSK)

This profile selects existing CKVF behavior for the SComm product. It does
not add a root key, a payload DEK, or a second file format. The confidentiality
root remains the VEK in [SPEC.md](../SPEC.md) §6.1. The MSK remains the
signing authority in §8. Decisions are recorded in [docs/adr](../../docs/adr).

## 1. What SComm stores

The payload holds cryptographic and security state: private signing and
encryption keys, OpenPGP and S/MIME material, PQC keys under the existing
`algorithm` / `algorithm_suite` fields, the MSK when the user keeps it in the
vault, recovery is represented only as unlock slots, device-slot metadata that
already fits `unlock_slots`, and key lifecycle fields from
[scomm-key-lifecycle.md](scomm-key-lifecycle.md).

The payload MUST NOT be used as a mailbox store. Mail bodies, attachments,
contacts, search indexes, embeddings, and mailbox databases stay outside CKVF.

## 2. Unlock

A SComm writer MUST persist at least one offline slot:

- `password-argon2id`, or
- `device-wrap-a256gcm`.

Both MAY be present. They wrap the same VEK.

SComm writers MUST NOT create `password-oprf-argon2id` or
`recovery-code-oprf-argon2id` slots. A recovery code is a high-entropy secret
placed in a `password-argon2id` slot. Argon2id parameters remain the slot
fields in SPEC.md §6.4. Writers use parameters at or above the floors in §6.5.

A SComm reader that is asked to open a container with no offline slot MUST
fail with a profile error (`ERR_SCOMM_OFFLINE_SLOT`) and MUST NOT contact a
vault host to evaluate pepper.

Discovery, a mailbox OTP, and an MSK public key MUST NOT be used as KDF input.

## 3. Custody of content keys

Exportability is not implied by a key record. The extension
`std:key-custody` ([registries/extensions.md](../../registries/extensions.md))
distinguishes:

| `custody` | `private_key` | Meaning |
| --- | --- | --- |
| `portable` | present, or null after `DELETE_PRIVATE_KEY` | Bytes may be copied inside the payload |
| `device-bound` | JSON `null` | Platform key (keystore, TPM, Secure Enclave, HSM). The record holds metadata and `key_ref` only |
| `external` | JSON `null` | A provider outside the device holds the key. The record holds `provider` and `key_ref` |

`device-bound` and `external` MUST be carried as a **critical** payload
extension so a reader that does not understand custody fails closed
(`ERR_CRITICAL_EXTENSION`) instead of treating the record as destroyed.

Absence of the extension means `portable`, which is the v1.0 behavior.

A device-bound key is not migrated by copying bytes. The new device creates
a new key record (new `absolute_key_id` / `scomm_key_id`) and Discovery
retires or revokes the previous public key through the directory lifecycle.

Merge MUST preserve `std:key-custody`. A `device-bound` or `external` record
MUST NOT gain `private_key` bytes from an older generation. A tombstone still
means destroyed and wins over custody.

## 4. Backup and sync

Backup is a retained CKVF container file (`vault.ckvf` or a generation
object). The user restores it explicitly. A later sync head does not make
that file undecryptable.

Sync is specified in [untrusted-sync.md](untrusted-sync.md). It is not a
backup, and it is not Discovery.

## 5. Devices

Device unlock uses `device-wrap-a256gcm` as in SPEC.md §10.4. Revoking a
device is an MSK-signed generation that removes that slot, samples a new
VEK, re-encrypts the one payload, and re-wraps every remaining slot
([docs/adr/0006](../../docs/adr/0006-device-revocation-rotates-vek.md)).

Revocation cannot erase a VEK or content key that the device already copied.

## 6. Lifecycle

Follow [scomm-key-lifecycle.md](scomm-key-lifecycle.md). Sync MUST NOT apply
a generation that lowers status severity or removes a tombstone.

## 7. Servers

No SComm origin is required to interpret or decrypt a container that follows
this profile. The optional [vault-host.md](vault-host.md) profile is not
this profile.

## 8. Security identities

Writers MAY store identity grouping in the non-critical payload extension
`priv:scomm.security-identities`. The extension data is a JSON object:

- `identities`: array of objects with `id`, `mailbox`, `experience`
  (`personal` or `managed`), `protocol` (`openPgp` or `smime`), `assurance`,
  `signingKeyIds`, `encryptionKeyIds`, and `defaultForMailbox`.

The extension is not a Discovery resource and MUST NOT contain private key
bytes. Readers that do not understand it MUST ignore it. A missing extension
means identities are derived from key family: OpenPGP keys are personal,
S/MIME keys are managed and self-issued. Derivation MUST NOT regenerate keys.
