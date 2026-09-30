# 0002. The VEK remains the confidentiality root

## Status

Accepted

## Context

CKVF already defines a random 256-bit Vault Encryption Key (VEK). AES-256-GCM under that VEK encrypts the payload. Each unlock slot wraps the same VEK with a key-encryption key (KEK): Argon2id for a password, or a device-held key for `device-wrap-a256gcm`. The Master Signing Key (MSK) signs lifecycle operations. SPEC.md forbids deriving the VEK from a password, and the MSK is not the AEAD key.

A later conceptual sketch used the name "Vault Root Key" (VRK) and a VEK → VRK → DEK stack. That name is not in CKVF.

## Decision

Keep the CKVF names and the existing envelope:

```text
VEK (random 256-bit confidentiality root)
  wrapped by password KEK (Argon2id)
  wrapped by device KEK (platform keystore)
  wrapped by future registered slot methods

MSK (Ed25519, or the registered hybrid form)
  authorizes mutations
  is not derived from the VEK
  is not a key-encryption key for the payload
```

Do not add a VRK, and do not insert a DEK between the VEK and the payload. Content keys remain ordinary key records inside the payload.

Compromise of the MSK does not reveal the VEK. Compromise of the VEK does not by itself authorize Discovery mutations. Impersonation of the directory identity requires the MSK private key, which lives inside the encrypted payload only when the user has stored it there.

## Consequences

Specifications, SDKs, and the SComm client say VEK, KEK, and MSK. They do not introduce VRK.
