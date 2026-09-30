# 0004. Synchronization uses immutable generations on untrusted storage

## Status

Accepted

## Context

CKVF already rejects silent last-writer-wins. Each container carries `generation`, `previous_generation_hash`, and `generation_hash`. Forks merge only after decrypt, under an MSK signature, with status severity `compromised > revoked > retired > active`.

A per-record journal or a second container version would duplicate that chain. The payload is one AEAD blob, so the generation file is already the immutable encrypted object.

## Decision

SComm synchronization stores CKVF containers as immutable generation objects plus a head pointer. The storage provider is untrusted. It may see object names, ciphertext, sizes, and access times. It must not need the VEK, a KEK, the MSK private key, or the recovery secret.

The head is compare-and-swap. A client that still holds a newer local generation refuses an older head. Wall-clock timestamps are not the ordering rule.

Backup and sync are different:

- Sync publishes the current chain so other authorized devices can catch up.
- A backup is a retained copy of a generation (usually the whole `vault.ckvf` file). A later revoke on the sync head does not make that backup file undecryptable. Restoring it is an explicit user action and must not run as an automatic sync pull.

Conflict handling stays the SPEC.md §12 merge. Security-critical status does not decrease. A tombstone is not removed by an older generation that still has `private_key` material.

## Consequences

There is no SComm-specific vault file extension. The portable artifact is a CKVF container. The sync layout is a profile on top of those files, not a new format.
