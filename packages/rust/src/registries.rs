//! CKVF registries (Community Draft 0.1).

pub const IDENTITY_TYPES: &[&str] = &["email", "dns"];
pub const KEY_FAMILIES: &[&str] = &["openpgp", "smime"];
pub const FORBIDDEN_FAMILIES: &[&str] = &["pq", "pqc", "post-quantum", "hybrid"];
pub const ALGORITHM_SUITES: &[&str] = &["rsa", "ecc", "pqc"];
pub const KEY_ENCODINGS: &[&str] = &["openpgp-tsk", "pkcs8", "pkcs12"];
pub const KEY_STATUSES: &[&str] = &["active", "retired", "revoked", "compromised"];
pub const KEY_PURPOSES: &[&str] = &["sign", "encrypt", "auth"];
pub const UNLOCK_METHODS: &[&str] = &[
    "password-argon2id",
    "device-wrap-a256gcm",
    "password-oprf-argon2id",
    "recovery-code-oprf-argon2id",
];
pub const PEPPER_UNLOCK_METHODS: &[&str] = &[
    "password-oprf-argon2id",
    "recovery-code-oprf-argon2id",
];
pub const AEAD_ALGORITHMS: &[&str] = &["A256GCM"];
pub const KDFS: &[&str] = &["Argon2id"];
pub const MSK_ALGORITHMS: &[&str] = &["Ed25519"];

pub fn status_severity(status: &str) -> i32 {
    match status {
        "active" => 0,
        "retired" => 1,
        "revoked" => 2,
        "compromised" => 3,
        _ => 0,
    }
}

pub fn is_forbidden_family(family: &str) -> bool {
    FORBIDDEN_FAMILIES.contains(&family)
}

/// Map a key algorithm string to CKVF `algorithm_suite`.
pub fn algorithm_suite_from_algorithm(algorithm: &str) -> Option<&'static str> {
    let n = algorithm.to_lowercase();
    if n.contains("mlkem")
        || n.contains("mldsa")
        || n.contains("ml-kem")
        || n.contains("ml-dsa")
        || n.contains("slhdsa")
        || n.contains("hqc")
        || n.starts_with("pqc-")
    {
        return Some("pqc");
    }
    if n.contains("rsa") {
        return Some("rsa");
    }
    if n.contains("ecdsa")
        || n.contains("ecdh")
        || n.contains("ed25519")
        || n.contains("ed448")
        || n.contains("x25519")
        || n.contains("x448")
        || n.contains("cv25519")
        || n.contains("cv448")
        || n == "ed25519"
    {
        return Some("ecc");
    }
    None
}
