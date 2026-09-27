# Extensions

Community registry of extension `id` values. SPEC.md Sections 4.6, 13, and Appendix A.8.

| id | critical typical | Specification |
| --- | --- | --- |
| `std:signing-key-retention` | `false` | [§ std:signing-key-retention](#stdsigning-key-retention) below |

## std:signing-key-retention

Location: payload `extensions` (or `critical_extensions` when a writer must
stop older readers from resurrecting deleted keys through merge).

```json
{
  "id": "std:signing-key-retention",
  "critical": false,
  "data": { "policy": "delete-on-retire" }
}
```

A decryption key must be kept after it is retired, or old mail becomes
unreadable (SPEC.md §9.6). A signing key has no such need: old signatures
are checked with the public key. Keeping a retired signing private key only
gives an attacker who opens the vault the ability to forge backdated
signatures.

When `data.policy` is `"delete-on-retire"`:

- When a key record whose `purpose` is exactly `["sign"]` (or `["sign",
  "auth"]`) leaves `active`, the writer MUST also apply an authorized
  `DELETE_PRIVATE_KEY` for it in the same generation. The record stays with
  `private_key: null`, its public key and status, and a tombstone.
- A record whose `purpose` includes `encrypt` is not affected. OpenPGP
  writers SHOULD keep signing and encryption in separate subkeys so the
  signing subkey can rotate on its own.
- Merge follows SPEC.md §12.4. Because each deletion is an authorized
  `DELETE_PRIVATE_KEY` with a tombstone, the deletion survives a merge with
  an older generation that still holds the key.

The public key stays in the vault and SHOULD stay published for
verification (for example, ten years after retirement in the Discovery
Protocol signing-key lookup).

Readers that do not implement this extension still read the vault correctly;
they may simply retain retired signing keys they create themselves.

## Identifier syntax

```
id = prefix ":" name
```

| Prefix | Namespace | Meaning |
| --- | --- | --- |
| `std:` | Standard | Assigned in this table (or a future IANA registry) |
| `exp:` | Experimental | MUST NOT be required for interoperability of core features |
| `priv:` | Private / vendor | MUST be collision-resistant (for example, reverse-DNS after `priv:`) |

`name` MUST match `^[a-z0-9][a-z0-9._-]*$`. The full `id` therefore matches `^(std|exp|priv):[a-z0-9][a-z0-9._-]*$`.

Each extension object is `{ "id", "critical", "data" }`. `data` MUST be present. `critical` MUST be `true` if and only if the object appears in a `critical_extensions` array, and MUST be `false` if and only if it appears in `extensions`.

## Processing

- Unknown **non-critical** extensions: preserve through read/write cycles that do not intentionally strip extensions; ignore `data` for security-sensitive processing.
- Unknown **critical** extensions: reject security-sensitive processing (`ERR_CRITICAL_EXTENSION`), including unlock for use, merge, and publication of keys derived from the vault.
- Core objects MUST NOT contain loose arbitrary JSON properties. Extensions are the only forward-compatible data channel.

## How to add a row

See [CONTRIBUTING.md](CONTRIBUTING.md). Standard (`std:`) entries require a specification reference and review. Experimental (`exp:`) entries MUST NOT be required to parse or unlock a v1.0 vault. Private (`priv:`) IDs MAY be used without a row in this table.
