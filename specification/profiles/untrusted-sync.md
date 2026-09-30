# Untrusted generation sync

**Status:** SComm.AI Draft  
**Applies to:** clients that replicate CKVF containers across devices  
**Container version:** unchanged (`"1.0"` / `"1.1"`)

Sync transports opaque CKVF generations. It does not define a new container
and it does not use Discovery as storage. The storage provider is untrusted.

## 1. Objects

A sync root contains one directory per `vault_id`:

```text
{root}/{vault_id}/head.json
{root}/{vault_id}/g/{generation}.json
```

`{generation}.json` is the CKVF container for that generation, canonical
enough that `generation_hash` verifies. Objects are immutable: a writer MUST
NOT replace `{generation}.json` with different bytes. If the name exists with
different bytes, the client treats that as tampering.

`head.json` is a pointer, not a second ciphertext:

```json
{
  "format": "CKVF-HEAD",
  "version": "1",
  "vault_id": "<same as the container>",
  "generation": 4,
  "generation_hash": "<generation_hash of that container>"
}
```

The pointed-to container MUST exist and MUST recompute to `generation_hash`.
The container's own `previous_generation_hash` chain is the authenticity
mechanism. `head.json` is not signed by itself. Clients MUST NOT trust the
head without loading the container and checking SPEC.md §6.2.

## 2. Compare-and-swap

Publish order:

1. Write the new generation object if absent.
2. Replace `head.json` only when the current head's `generation_hash` equals
   the parent's `previous_generation_hash` (or the head is absent and this is
   generation 1).

A lost race leaves an immutable orphan generation. The client merges under
SPEC.md §12 and retries with a new generation. There is no last-writer-wins
on the payload.

Wall-clock timestamps MUST NOT decide which head wins.

## 3. Rollback

Each device remembers the highest `(generation, generation_hash)` it has
accepted for that `vault_id`.

If a head points at a generation lower than that remembered head, or at a
hash that is not a descendant of it, the client MUST refuse to adopt it as
the sync head (`ERR_ROLLBACK`). It MAY still open that container when the
user explicitly restores a backup.

An explicit backup restore does not promise that later revocations are
present. The user is choosing a historical ciphertext. Sync after a restore
MUST NOT silently republish that historical generation over a newer head
that other devices already accepted.

## 4. What the provider can see

Unavoidable metadata:

- the `vault_id` directory name (16 random bytes, base64url);
- generation numbers in object names;
- ciphertext sizes;
- write and read timing.

The provider does not need plaintext keys, payload metadata, the VEK, a
KEK, the MSK seed, or the recovery secret. Object names are not required
to be encrypted; generation numbers leak update order.

## 5. Merge dominance

Ordinary metadata follows SPEC.md §12. Security-critical lifecycle does not
use a generic last-write or CRDT:

- status severity `compromised > revoked > retired > active` is monotonic;
- a tombstone is not cleared by a generation that still holds `private_key`;
- a device slot removed by a revocation generation is not restored by an
  older container;
- MSK `current` mismatch is `ERR_MERGE_MSK`, as in the existing merge-conflict
  vector.

Deleted or revoked state is therefore not resurrected by a stale device that
still holds an older file.

## 6. Backup is not sync

Copying `vault.ckvf` (or one generation file) to removable media is a backup.
Deleting or revoking through sync does not rotate the VEK inside that old
file. Applications MUST present restore as a separate action from sync.

## 7. Transports

The engine speaks only the operations above: list generations, get, put if
absent, get head, compare-and-swap head. A local directory is the first
transport. WebDAV and other providers are adapters. None of them is
`vault.scomm.ai`, and none of them is Discovery.

A WebDAV adapter maps those operations onto HTTP. `PUT` of
`g/{generation}.json` uses `If-None-Match: *`. A `412` whose body differs is
tampering. `PUT` of `head.json` uses `If-None-Match: *` when the head is
absent, and `If-Match: "<generation_hash>"` when replacing it.

Direct device transfer is not a sync write. The new device writes a CPace
request to `{root}/pair/{session}.json`. The approving device answers in
that file with the container and a Vault Encryption Key sealed to the CPace
key. A QR code carries `scomm-pair:v2` so the approving device can find the
session. Both devices must see the folder. The code does not upload the vault.
