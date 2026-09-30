# Algorithms and suites

Community registry of key-record `algorithm` and `algorithm_suite` strings, plus MSK `algorithm`. SPEC.md Sections 9.3, Appendix A.3, and Appendix A.4.

`algorithm` identifies the primary public-key algorithm. `algorithm_suite` is JSON `null` for a single classical algorithm, or a registry identifier for a composite, hybrid, or otherwise coupled suite (including PQC hybrids).

Implementations MUST accept the v1.0 starting-set strings and MAY accept additional registered strings. Implementations MUST NOT infer `family` from `algorithm`.

PQC identifiers are **algorithm / suite values**, never a key family. Store them under `family` `"openpgp"` or `"smime"`.

Writers SHOULD use the identifier from the native family specification when that specification has a stable name.

## v1.0 starting set (SPEC Appendix A.3)

| Value | Typical family | Notes |
| --- | --- | --- |
| `Ed25519` | openpgp, MSK | RFC 8032. MSK `algorithm` MUST be this string in protocol `"1.0"`. |
| `Ed448` | openpgp | RFC 8032 |
| `X25519` | openpgp | RFC 7748 / RFC 9580 |
| `X448` | openpgp | RFC 7748 / RFC 9580 |
| `NIST-P-256` | openpgp, smime | |
| `NIST-P-384` | openpgp, smime | |
| `NIST-P-521` | openpgp, smime | |
| `RSA-2048` | openpgp, smime | |
| `RSA-3072` | openpgp, smime | |
| `RSA-4096` | openpgp, smime | |
| `ML-KEM-768` | openpgp or smime | PQC algorithm, not a family |
| `ML-DSA-65` | openpgp or smime | PQC algorithm, not a family |
| `SLH-DSA-SHA2-128s` | openpgp or smime | PQC algorithm, not a family |

## Additional registered identifiers

These strings are registered for community use (S/MIME, historical OpenPGP nicknames, and short names). They do not replace the starting set.

| Value | Typical family | Notes |
| --- | --- | --- |
| `rsa` | openpgp, smime | Generic RSA; prefer a sized starting-set value when known |
| `rsa-pss` | smime | RSASSA-PSS (PKIX / S/MIME) |
| `ecdsa-p256` | openpgp, smime | ECDSA with NIST P-256 |
| `ecdsa-p384` | openpgp, smime | ECDSA with NIST P-384 |
| `cv25519` | openpgp | Historical Curve25519 ECDH name used by some OpenPGP implementations; prefer `X25519` for new records |
| `x25519` | openpgp | Alias of `X25519`; writers SHOULD use `X25519` |
| `x448` | openpgp | Alias of `X448`; writers SHOULD use `X448` |
| `ed448` | openpgp | Alias of `Ed448`; writers SHOULD use `Ed448` |

## OpenPGP public-key algorithm names (RFC 9580)

When storing OpenPGP keys, `algorithm` MAY be the RFC 9580 / IANA OpenPGP Public Key Algorithms **name** (cite RFC 9580; do not copy RFC text). Numeric OpenPGP algorithm IDs are not CKVF `algorithm` values.

| OpenPGP name | Typical CKVF `algorithm` |
| --- | --- |
| RSA (Encrypt or Sign) | `rsa` or a sized `RSA-*` value |
| RSA Encrypt-Only | `rsa` |
| RSA Sign-Only | `rsa` |
| Elgamal (Encrypt-Only) | `Elgamal` (registered here; not in the starting set) |
| DSA | `DSA` (registered here; not in the starting set) |
| ECDH | curve-specific (`X25519`, `cv25519`, `NIST-P-*`) |
| ECDSA | `ecdsa-p256`, `ecdsa-p384`, or `NIST-P-*` |
| EdDSALegacy | Deprecated; MUST NOT be written for new keys |
| X25519 | `X25519` |
| X448 | `X448` |
| Ed25519 | `Ed25519` |
| Ed448 | `Ed448` |

Registered OpenPGP-name strings: `RSA (Encrypt or Sign)`, `RSA Encrypt-Only`, `RSA Sign-Only`, `Elgamal (Encrypt-Only)`, `DSA`, `ECDH`, `ECDSA`, `EdDSALegacy`, `X25519`, `X448`, `Ed25519`, `Ed448`.

## RFC 9980 PQC in OpenPGP (algorithm / suite under `openpgp`)

[RFC 9980](https://www.rfc-editor.org/rfc/rfc9980.html) identifiers MUST be stored with `family` `"openpgp"`. Use `algorithm` for a standalone scheme and `algorithm_suite` (or `algorithm`) for a composite. They MUST NOT appear as a CKVF family.

| Value | OpenPGP ID | Role | Suggested fields |
| --- | --- | --- | --- |
| `ML-DSA-65+Ed25519` | 30 | Composite signature | `algorithm` or `algorithm_suite` |
| `ML-DSA-87+Ed448` | 31 | Composite signature | `algorithm` or `algorithm_suite` |
| `SLH-DSA-SHAKE-128s` | 32 | Standalone signature | `algorithm`; `algorithm_suite` `null` |
| `SLH-DSA-SHAKE-128f` | 33 | Standalone signature | `algorithm`; `algorithm_suite` `null` |
| `SLH-DSA-SHAKE-256s` | 34 | Standalone signature | `algorithm`; `algorithm_suite` `null` |
| `ML-KEM-768+X25519` | 35 | Composite KEM | `algorithm` or `algorithm_suite` |
| `ML-KEM-1024+X448` | 36 | Composite KEM | `algorithm` or `algorithm_suite` |

Cite RFC 9980. Do not copy RFC text.

## Algorithm suites (SPEC Appendix A.4)

| Value | Meaning |
| --- | --- |
| `null` | Single algorithm in `algorithm` |
| `ML-DSA-65+Ed25519` | RFC 9980 algorithm 30 |
| `ML-DSA-87+Ed448` | RFC 9980 algorithm 31 |
| `SLH-DSA-SHAKE-128s` | RFC 9980 algorithm 32 |
| `SLH-DSA-SHAKE-128f` | RFC 9980 algorithm 33 |
| `SLH-DSA-SHAKE-256s` | RFC 9980 algorithm 34 |
| `ML-KEM-768+X25519` | RFC 9980 algorithm 35 |
| `ML-KEM-1024+X448` | RFC 9980 algorithm 36 |
| `smime-composite-draft` | Placeholder for composite PKIX/S/MIME suites |

Writers SHOULD use the suite identifier from the native family specification rather than these placeholders when that specification has a stable name.
