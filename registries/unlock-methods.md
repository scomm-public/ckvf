# Unlock methods

Community registry of unlock-slot `method` values. SPEC.md Sections 4.2, 10, and Appendix A.1.

| Value | KDF | Wrap | Specification |
| --- | --- | --- | --- |
| `password-argon2id` | Argon2id (`kdf` REQUIRED) | `A256GCM` | This specification |
| `device-wrap-a256gcm` | none in-file (`kdf` omitted) | `A256GCM` | This specification (KEK storage out of scope) |
| `password-oprf-argon2id` | POPRF (`oprf` REQUIRED) then Argon2id (`kdf` REQUIRED, `m` ≥ 65536, `t` ≥ 3) | `A256GCM` | [profiles/pepper-oprf.md](../specification/profiles/pepper-oprf.md) |
| `recovery-code-oprf-argon2id` | same as above; secret is a recovery code | `A256GCM` | [profiles/pepper-oprf.md](../specification/profiles/pepper-oprf.md) |

All slots MUST wrap the **same** current VEK. `slot_id` values MUST be unique within a container (`ERR_SLOT_ID`).

Passwords MUST NOT be stored. Implementations MUST NOT write a password, password hash, or password verifier into the container, payload, or extensions.

Device-oriented methods MAY omit `kdf` and obtain a KEK from platform secure storage. No vendor secure-storage API is normative. The wrap object remains in the file so the wrapped VEK is portable. `ADD_DEVICE` / `REMOVE_DEVICE` authorize slot-set changes.

Writers SHOULD persist at least one `"password-argon2id"` slot so the vault remains unlockable if a device is lost, unless a registered recovery profile provides an equivalent. A `"password-oprf-argon2id"` or `"recovery-code-oprf-argon2id"` slot is such an equivalent, with the trade-off that it needs the vault host online to unlock.
