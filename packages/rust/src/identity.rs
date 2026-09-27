//! Identity canonicalization and identity_id.

use unicode_normalization::UnicodeNormalization;

use crate::b64;
use crate::crypto::sha256;
use crate::errors::{fail_msg, CkvfError};
use crate::limits::DEFAULT_LIMITS;
use crate::types::Identity;

pub fn identity_id(r#type: &str, canonical_value: &str) -> String {
    let input = format!("{type}:{canonical_value}");
    b64::encode(&sha256(input.as_bytes()))
}

pub fn canonicalize_email(raw: &str) -> Result<String, CkvfError> {
    let nfc: String = raw.nfc().collect::<String>().trim().to_string();
    let at = nfc.rfind('@').ok_or_else(|| {
        CkvfError::msg(
            "ERR_IDENTITY_CANON",
            "email must contain a non-empty local-part and domain",
        )
    })?;
    if at == 0 || at == nfc.len() - 1 {
        return fail_msg(
            "ERR_IDENTITY_CANON",
            "email must contain a non-empty local-part and domain",
        );
    }
    let local = &nfc[..at];
    let domain = &nfc[at + 1..];
    if local.bytes().any(|b| b > 0x7f) {
        return fail_msg("ERR_IDENTITY_CANON", "v1.0 email local-part must be ASCII");
    }
    if nfc.as_bytes().len() > DEFAULT_LIMITS.max_identity_bytes {
        return fail_msg("ERR_PARSER_LIMIT", "identity too long");
    }
    let local_lower: String = local
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect();
    let domain = canonicalize_dns(domain)?;
    Ok(format!("{local_lower}@{domain}"))
}

pub fn canonicalize_dns(raw: &str) -> Result<String, CkvfError> {
    let mut s: String = raw.nfc().collect::<String>().trim().to_string();
    while s.ends_with('.') {
        s.pop();
    }
    if s.is_empty() {
        return fail_msg("ERR_IDENTITY_CANON", "empty DNS name");
    }
    if s.as_bytes().len() > DEFAULT_LIMITS.max_identity_bytes {
        return fail_msg("ERR_PARSER_LIMIT", "identity too long");
    }
    let mut labels = Vec::new();
    for label in s.split('.') {
        if label.is_empty() {
            return fail_msg("ERR_IDENTITY_CANON", "empty DNS label");
        }
        if label.bytes().all(|b| b <= 0x7f) {
            labels.push(label.to_ascii_lowercase());
        } else {
            let lower: String = label.nfc().collect::<String>().to_lowercase();
            labels.push(format!("xn--{}", punycode_encode(&lower)?));
        }
    }
    let ascii = labels.join(".");
    if ascii.ends_with('.') {
        return fail_msg("ERR_IDENTITY_CANON", "trailing dot after IDNA");
    }
    Ok(ascii)
}

pub fn make_identity(r#type: &str, raw_value: &str) -> Result<Identity, CkvfError> {
    let value = if r#type == "email" {
        canonicalize_email(raw_value)?
    } else {
        canonicalize_dns(raw_value)?
    };
    let id = identity_id(r#type, &value);
    Ok(Identity {
        r#type: r#type.to_string(),
        value,
        identity_id: id,
    })
}

pub fn assert_identity(identity: &Identity) -> Result<(), CkvfError> {
    let expected_value = if identity.r#type == "email" {
        canonicalize_email(&identity.value)?
    } else {
        canonicalize_dns(&identity.value)?
    };
    if expected_value != identity.value {
        return fail_msg("ERR_IDENTITY_CANON", "identity.value is not canonical");
    }
    let expected = identity_id(&identity.r#type, &identity.value);
    if expected != identity.identity_id {
        return fail_msg("ERR_IDENTITY_ID", "identity_id mismatch");
    }
    Ok(())
}

fn punycode_encode(input: &str) -> Result<String, CkvfError> {
    const N0: u32 = 128;
    const BIAS0: u32 = 72;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const BASE: u32 = 36;

    let input_cps: Vec<u32> = input.chars().map(|c| c as u32).collect();
    let mut output = String::new();
    let basic: Vec<u32> = input_cps.iter().copied().filter(|c| *c < 128).collect();
    for c in &basic {
        output.push(char::from_u32(*c).unwrap_or('?'));
    }
    let mut handled = basic.len();
    if handled > 0 {
        output.push('-');
    }
    let mut n = N0;
    let mut delta: u32 = 0;
    let mut bias = BIAS0;
    while handled < input_cps.len() {
        let mut m = 1u32 << 30;
        for &c in &input_cps {
            if c >= n && c < m {
                m = c;
            }
        }
        delta = delta
            .checked_add(
                (m - n)
                    .checked_mul((handled as u32) + 1)
                    .ok_or_else(|| CkvfError::msg("ERR_IDENTITY_CANON", "punycode overflow"))?,
            )
            .ok_or_else(|| CkvfError::msg("ERR_IDENTITY_CANON", "punycode overflow"))?;
        n = m;
        for &c in &input_cps {
            if c < n {
                delta = delta
                    .checked_add(1)
                    .ok_or_else(|| CkvfError::msg("ERR_IDENTITY_CANON", "punycode overflow"))?;
            } else if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        output.push(encode_digit(q));
                        break;
                    }
                    output.push(encode_digit(t + ((q - t) % (BASE - t))));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                bias = adapt(delta, (handled as u32) + 1, handled == basic.len());
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    Ok(output)
}

fn encode_digit(d: u32) -> char {
    char::from_u32(d + 22 + 75 * if d < 26 { 1 } else { 0 }).unwrap_or('?')
}

fn adapt(delta_in: u32, num_points: u32, first_time: bool) -> u32 {
    let mut d = if first_time { delta_in / 700 } else { delta_in >> 1 };
    d += d / num_points;
    let mut k = 0u32;
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    while d > ((BASE - TMIN) * TMAX) / 2 {
        d /= BASE - TMIN;
        k += BASE;
    }
    k + ((BASE - TMIN + 1) * d) / (d + SKEW)
}
