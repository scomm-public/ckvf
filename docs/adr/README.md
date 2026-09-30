# Architecture decision records

These records state how SComm uses CKVF. They do not replace [SPEC.md](../../specification/SPEC.md).

| Record | Decision |
| --- | --- |
| [0001](0001-discovery-hosted-vault-retired.md) | Discovery stays hosted. SComm does not host Vault ciphertext. |
| [0002](0002-vek-is-the-confidentiality-root.md) | The VEK stays the envelope root. There is no VRK layer. |
| [0003](0003-scomm-unlock-is-offline.md) | SComm unlock does not depend on a vault host or pepper OPRF. |
| [0004](0004-untrusted-generation-sync.md) | Sync copies immutable generations to storage the user chooses. |
| [0005](0005-discovery-otp-does-not-decrypt.md) | Mailbox OTP can replace an MSK. It cannot decrypt a vault. |
| [0006](0006-device-revocation-rotates-vek.md) | Revoking a device drops its slot and rotates the VEK. |
