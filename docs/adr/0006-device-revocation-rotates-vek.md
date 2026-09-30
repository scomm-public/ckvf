# 0006. Device revocation drops a slot and rotates the VEK

## Status

Accepted

## Context

A device slot wraps the VEK. Removing the slot stops that device from unwrapping future containers with its KEK. It does not erase a VEK the device already unwrapped, or any private keys it already copied.

Because the payload is a single AEAD under the VEK, rotating the VEK re-encrypts that one payload and re-wraps the remaining slots. It does not require a new key hierarchy.

## Decision

Revocation is an MSK-signed generation that:

1. omits the revoked device slot;
2. samples a new random VEK;
3. re-encrypts the payload under the new VEK;
4. re-wraps the new VEK for every remaining slot.

Other devices accept the generation through the hash chain. A later mutation signed or wrapped only for the revoked device is rejected once those devices have seen the revocation generation.

This does not claim that revocation wipes secrets the revoked device already decrypted.

Device-bound content keys (a Secure Enclave or TPM key with no exportable private bytes) are described by the `std:key-custody` extension in the local-vault profile. They are not copied by wrapping the VEK. Moving to a new device means a new key record and a new `scomm_key_id`, then retiring the old public key in Discovery.

## Consequences

Sync implementations must treat device revocation as monotonic: a stale device cannot put its slot back by replaying an older generation as the head.
