//! CKVF error codes (Community Draft 0.1).

use thiserror::Error;

pub const ERROR_CODES: &[&str] = &[
    "ERR_FORMAT",
    "ERR_VERSION",
    "ERR_JSON",
    "ERR_JCS",
    "ERR_BASE64",
    "ERR_PARSER_LIMIT",
    "ERR_AEAD_DECRYPT",
    "ERR_WRAP_DECRYPT",
    "ERR_KDF",
    "ERR_GENERATION_HASH",
    "ERR_GENERATION_CONFLICT",
    "ERR_STALE_GENERATION",
    "ERR_IDENTITY_ID",
    "ERR_IDENTITY_CANON",
    "ERR_IDENTITY_MISMATCH",
    "ERR_MSK",
    "ERR_MSK_EXISTS",
    "ERR_SIGNATURE",
    "ERR_PAYLOAD_HASH",
    "ERR_REPLAY",
    "ERR_OPERATION",
    "ERR_SHORT_KEY_ID",
    "ERR_KEY_ID",
    "ERR_FAMILY",
    "ERR_ENCODING",
    "ERR_STATUS",
    "ERR_SLOT_ID",
    "ERR_CRITICAL_EXTENSION",
    "ERR_EXTENSION",
    "ERR_MERGE_MSK",
    "ERR_MERGE_PREFERRED_KEY",
    "ERR_MERGE_SLOT",
    "ERR_MERGE_VEK",
    "ERR_MERGE_PRIVATE_KEY",
    "ERR_OWNERSHIP",
    "ERR_NOT_IMPLEMENTED",
    "ERR_UNLOCK",
    "ERR_INTERNAL",
];

#[derive(Debug, Error, Clone)]
pub enum CkvfError {
    #[error("CkvfException({code})")]
    Code {
        code: &'static str,
    },
    #[error("CkvfException({code}: {message})")]
    WithMessage {
        code: &'static str,
        message: String,
    },
}

impl CkvfError {
    pub fn new(code: &'static str) -> Self {
        Self::Code { code }
    }

    pub fn msg(code: &'static str, message: impl Into<String>) -> Self {
        Self::WithMessage {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Code { code } | Self::WithMessage { code, .. } => code,
        }
    }
}

pub fn fail<T>(code: &'static str) -> Result<T, CkvfError> {
    Err(CkvfError::new(code))
}

pub fn fail_msg<T>(code: &'static str, message: impl Into<String>) -> Result<T, CkvfError> {
    Err(CkvfError::msg(code, message))
}
