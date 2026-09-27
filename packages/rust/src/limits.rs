//! Parser and KDF limits.

#[derive(Debug, Clone, Copy)]
pub struct ParserLimits {
    pub max_vault_bytes: usize,
    pub max_payload_bytes: usize,
    pub max_json_nesting: usize,
    pub max_key_count: usize,
    pub max_key_bytes: usize,
    pub max_extension_bytes: usize,
    pub max_unlock_slots: usize,
    pub max_tombstones: usize,
    pub max_extensions: usize,
    pub max_argon2_memory_kib: u32,
    pub max_argon2_time: u32,
    pub max_argon2_parallelism: u32,
    pub min_argon2_memory_kib: u32,
    pub min_argon2_time: u32,
    pub min_argon2_parallelism: u32,
    pub max_identity_bytes: usize,
}

pub const DEFAULT_LIMITS: ParserLimits = ParserLimits {
    max_vault_bytes: 16 * 1024 * 1024,
    max_payload_bytes: 16 * 1024 * 1024,
    max_json_nesting: 32,
    max_key_count: 1024,
    max_key_bytes: 1024 * 1024,
    max_extension_bytes: 64 * 1024,
    max_unlock_slots: 64,
    max_tombstones: 1024,
    max_extensions: 64,
    max_argon2_memory_kib: 1_048_576,
    max_argon2_time: 16,
    max_argon2_parallelism: 16,
    min_argon2_memory_kib: 16_384,
    min_argon2_time: 2,
    min_argon2_parallelism: 1,
    max_identity_bytes: 2048,
};

#[derive(Debug, Clone, Copy)]
pub struct Argon2idParams {
    pub alg: &'static str,
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub key_length: u32,
}

pub const RECOMMENDED_ARGON2ID: Argon2idParams = Argon2idParams {
    alg: "Argon2id",
    m: 65536,
    t: 3,
    p: 4,
    key_length: 32,
};

/// Floor for `*-oprf-argon2id` slots.
pub const PEPPER_MIN_ARGON2ID: Argon2idParams = Argon2idParams {
    alg: "Argon2id",
    m: 65536,
    t: 3,
    p: 1,
    key_length: 32,
};

/// Legal for tests/CI; still meets SPEC §6.5 minima.
pub const TEST_ARGON2ID: Argon2idParams = Argon2idParams {
    alg: "Argon2id",
    m: 16384,
    t: 2,
    p: 1,
    key_length: 32,
};
