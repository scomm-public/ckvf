# SComm key lifecycle profile

**Status:** SComm.AI Draft  
**Applies to:** CKVF writers and readers used by SComm Discovery, SDKs, and Scomm.AI

Normative lifecycle semantics live in the Discovery Protocol
`spec/key-lifecycle.md`. This profile is how a CKVF container carries that
model without changing the v1.0 `status` enum.

## 1. What the container stores

| CKVF field | SComm dimension |
| --- | --- |
| `status` | Cryptographic lifecycle projection: `active`, `retired`, `revoked`. Legacy `compromised` projects to `revoked` + reason `KEY_COMPROMISE`. |
| `private_key` | Material. Present means `hot`. JSON `null` after `DELETE_PRIVATE_KEY` means `destroyed`. |
| Tombstone | Evidence of destruction. It does not revoke and it does not retire. |
| `purpose` | `sign` and/or `encrypt` as CKVF already defines. A directory artifact still has one SComm purpose. |

CKVF has no publication field. Discovery `published`, `withdrawn`, and
`tombstoned` are directory facts. A vault MUST NOT invent them by deleting
`public_key` on retire.

Cold material state `archived` is not a CKVF 1.0 status. Restoring a copy
into the container does not set `status` back to `active`.

## 2. Operations

| User intent | CKVF | Directory |
| --- | --- | --- |
| Retire | `RETIRE_KEY` → `status: retired`. Private key stays. | `retire_key`. Public bytes stay. |
| Revoke | `REVOKE_KEY` → `status: revoked`. Private key stays. | `revoke_key` with a reason. |
| Stop publishing | No container change required. | `withdraw_key`. |
| Destroy private key | `DELETE_PRIVATE_KEY` and a tombstone. `status` unchanged. | No directory operation. |

`RETIRE_KEY` MUST NOT call `DELETE_PRIVATE_KEY`.
`REVOKE_KEY` MUST NOT call `DELETE_PRIVATE_KEY`.

Extension `std:signing-key-retention` policy `delete-on-retire` MUST NOT be
written by this profile. See [registries/extensions.md](../../registries/extensions.md).

## 3. Projection rules

- Merge severity stays `compromised > revoked > retired > active`.
- A reader projecting into SComm lifecycle MUST map `compromised` to
  `revoked` and reason `KEY_COMPROMISE`.
- `retired` MUST NOT be presented as deleted.
- An encryption record with `status` `retired` or `revoked` and a present
  `private_key` MAY decrypt historical ciphertext.
- A sign-only record with `private_key: null` MAY still verify using the
  directory public key. Verification does not require the private key.

## 4. Out of scope

This profile does not change container version `1.0`, the `status` enum, or
MSK arm and replace.
