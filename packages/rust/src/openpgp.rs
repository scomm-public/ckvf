//! Minimal OpenPGP packet helpers for canonical public-key derivation.

use crate::errors::{fail, fail_msg, CkvfError};

pub fn canonical_openpgp_public_key(
    public_key_packet: &[u8],
    tsk: Option<&[u8]>,
) -> Result<Vec<u8>, CkvfError> {
    let source: &[u8] = if !public_key_packet.is_empty() {
        public_key_packet
    } else {
        tsk.ok_or_else(|| CkvfError::msg("ERR_ENCODING", "missing OpenPGP key material"))?
    };
    if is_single_public_key_packet(source)? {
        return ensure_new_format_tag6(source);
    }
    if let Some(tsk) = tsk {
        if !tsk.is_empty() {
            if let Some(extracted) = extract_primary_public_key(tsk)? {
                return Ok(extracted);
            }
        }
    }
    if let Some(extracted) = extract_primary_public_key(source)? {
        return Ok(extracted);
    }
    fail_msg(
        "ERR_ENCODING",
        "unable to derive canonical OpenPGP Public-Key packet",
    )
}

fn extract_primary_public_key(bytes: &[u8]) -> Result<Option<Vec<u8>>, CkvfError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let Some(parsed) = parse_packet(bytes, offset)? else {
            break;
        };
        if parsed.tag == 6 {
            return Ok(Some(encode_new_format_packet(6, &parsed.body)));
        }
        if parsed.tag == 5 {
            let body = public_body_from_secret(&parsed.body)?;
            return Ok(Some(encode_new_format_packet(6, &body)));
        }
        offset = parsed.next;
    }
    Ok(None)
}

fn is_single_public_key_packet(bytes: &[u8]) -> Result<bool, CkvfError> {
    let Some(parsed) = parse_packet(bytes, 0)? else {
        return Ok(false);
    };
    Ok(parsed.tag == 6 && parsed.next == bytes.len())
}

fn ensure_new_format_tag6(bytes: &[u8]) -> Result<Vec<u8>, CkvfError> {
    let parsed = parse_packet(bytes, 0)?
        .ok_or_else(|| CkvfError::msg("ERR_ENCODING", "not a Public-Key packet"))?;
    if parsed.tag != 6 {
        return fail_msg("ERR_ENCODING", "not a Public-Key packet");
    }
    Ok(encode_new_format_packet(6, &parsed.body))
}

fn public_body_from_secret(secret_body: &[u8]) -> Result<Vec<u8>, CkvfError> {
    if secret_body.len() < 6 {
        return fail_msg("ERR_ENCODING", "truncated Secret-Key packet");
    }
    let version = secret_body[0];
    if version == 4 {
        let mut pos = 1 + 4 + 1;
        let algo = secret_body[5];
        pos += public_material_length(secret_body, pos, algo, version)?;
        return Ok(secret_body[..pos].to_vec());
    }
    if version == 6 {
        let pos = 1 + 4 + 1 + 4;
        let key_octets = read_u32(secret_body, 6)? as usize;
        if pos + key_octets > secret_body.len() {
            return fail_msg("ERR_ENCODING", "truncated v6 key");
        }
        return Ok(secret_body[..pos + key_octets].to_vec());
    }
    fail_msg(
        "ERR_ENCODING",
        format!("unsupported OpenPGP key version {version}"),
    )
}

fn public_material_length(
    body: &[u8],
    pos: usize,
    algo: u8,
    version: u8,
) -> Result<usize, CkvfError> {
    reject_rfc9980_version(version, algo)?;
    match algo {
        1 | 2 | 3 => {
            let p1 = mpi_len(body, pos)?;
            Ok(p1 + mpi_len(body, pos + p1)?)
        }
        16 => {
            let p1 = mpi_len(body, pos)?;
            let p2 = mpi_len(body, pos + p1)?;
            let p3 = mpi_len(body, pos + p1 + p2)?;
            Ok(p1 + p2 + p3)
        }
        17 => {
            let mut p = pos;
            p += mpi_len(body, p)?;
            p += mpi_len(body, p)?;
            p += mpi_len(body, p)?;
            p += mpi_len(body, p)?;
            Ok(p - pos)
        }
        18 | 19 | 22 => {
            if pos >= body.len() {
                return fail_msg("ERR_ENCODING", "truncated MPI");
            }
            let oid_len = body[pos] as usize;
            let mut p = pos + 1 + oid_len;
            p += mpi_len(body, p)?;
            if algo == 18 {
                if p >= body.len() {
                    return fail_msg("ERR_ENCODING", "truncated MPI");
                }
                let kdf_len = body[p] as usize;
                p += 1 + kdf_len;
            }
            Ok(p - pos)
        }
        25 | 27 => Ok(32),
        26 => Ok(56),
        28 => Ok(57),
        30 => Ok(32 + 1952),
        31 => Ok(57 + 2592),
        32 | 33 => Ok(32),
        34 => Ok(64),
        35 => Ok(32 + 1184),
        36 => Ok(56 + 1568),
        105 | 106 => fail_msg("ERR_ENCODING", "LibrePGP Kyber is not RFC 9980"),
        _ => fail_msg("ERR_ENCODING", format!("unsupported OpenPGP algorithm {algo}")),
    }
}

fn reject_rfc9980_version(version: u8, algo: u8) -> Result<(), CkvfError> {
    if !(30..=36).contains(&algo) {
        return Ok(());
    }
    if algo == 35 {
        if version == 4 || version == 6 {
            return Ok(());
        }
        return fail_msg("ERR_ENCODING", "algorithm 35 requires OpenPGP version 4 or 6");
    }
    if version != 6 {
        return fail_msg(
            "ERR_ENCODING",
            format!("RFC 9980 algorithm {algo} requires OpenPGP version 6"),
        );
    }
    Ok(())
}

fn mpi_len(body: &[u8], pos: usize) -> Result<usize, CkvfError> {
    if pos + 2 > body.len() {
        return fail_msg("ERR_ENCODING", "truncated MPI");
    }
    let bits = ((body[pos] as usize) << 8) | (body[pos + 1] as usize);
    Ok(2 + (bits + 7) / 8)
}

fn read_u32(body: &[u8], pos: usize) -> Result<u32, CkvfError> {
    if pos + 4 > body.len() {
        return fail("ERR_ENCODING");
    }
    Ok(((body[pos] as u32) << 24)
        | ((body[pos + 1] as u32) << 16)
        | ((body[pos + 2] as u32) << 8)
        | (body[pos + 3] as u32))
}

struct ParsedPacket {
    tag: u8,
    body: Vec<u8>,
    next: usize,
}

fn parse_packet(bytes: &[u8], offset: usize) -> Result<Option<ParsedPacket>, CkvfError> {
    if offset >= bytes.len() {
        return Ok(None);
    }
    let hdr = bytes[offset];
    if (hdr & 0x80) == 0 {
        return fail_msg("ERR_ENCODING", "invalid OpenPGP packet header");
    }
    let new_format = (hdr & 0x40) != 0;
    if new_format {
        let tag = hdr & 0x3f;
        let mut pos = offset + 1;
        let (len, consumed) = read_new_length(bytes, pos)?;
        pos += consumed;
        if pos + len > bytes.len() {
            return fail_msg("ERR_ENCODING", "truncated packet");
        }
        let body = bytes[pos..pos + len].to_vec();
        return Ok(Some(ParsedPacket {
            tag,
            body,
            next: pos + len,
        }));
    }
    let tag = (hdr >> 2) & 0x0f;
    let len_type = hdr & 0x03;
    let mut pos = offset + 1;
    let len = match len_type {
        0 => {
            if pos >= bytes.len() {
                return fail("ERR_ENCODING");
            }
            let l = bytes[pos] as usize;
            pos += 1;
            l
        }
        1 => {
            if pos + 2 > bytes.len() {
                return fail("ERR_ENCODING");
            }
            let l = ((bytes[pos] as usize) << 8) | (bytes[pos + 1] as usize);
            pos += 2;
            l
        }
        2 => {
            let l = read_u32(bytes, pos)? as usize;
            pos += 4;
            l
        }
        _ => return fail_msg("ERR_ENCODING", "indeterminate OpenPGP packet length"),
    };
    if pos + len > bytes.len() {
        return fail_msg("ERR_ENCODING", "truncated packet");
    }
    let body = bytes[pos..pos + len].to_vec();
    Ok(Some(ParsedPacket {
        tag,
        body,
        next: pos + len,
    }))
}

fn read_new_length(bytes: &[u8], pos: usize) -> Result<(usize, usize), CkvfError> {
    if pos >= bytes.len() {
        return fail("ERR_ENCODING");
    }
    let o1 = bytes[pos];
    if o1 < 192 {
        return Ok((o1 as usize, 1));
    }
    if o1 < 224 {
        if pos + 1 >= bytes.len() {
            return fail("ERR_ENCODING");
        }
        return Ok((((o1 as usize - 192) << 8) + (bytes[pos + 1] as usize) + 192, 2));
    }
    if o1 == 255 {
        let len = read_u32(bytes, pos + 1)? as usize;
        return Ok((len, 5));
    }
    fail_msg("ERR_ENCODING", "partial body length not allowed in keys")
}

pub fn encode_new_format_packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut hdr = if len < 192 {
        vec![0xc0 | tag, len as u8]
    } else if len < 8384 {
        let d = len - 192;
        vec![0xc0 | tag, ((d >> 8) + 192) as u8, (d & 0xff) as u8]
    } else {
        vec![
            0xc0 | tag,
            255,
            ((len >> 24) & 0xff) as u8,
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]
    };
    hdr.extend_from_slice(body);
    hdr
}

/// Minimal RFC 9580 v4 Ed25519 (algo 27) unencrypted TSK. TEST KEYS ONLY.
pub fn build_openpgp_ed25519_tsk(
    seed: &[u8],
    public_key: &[u8],
    created_at_unix: u32,
) -> Result<Vec<u8>, CkvfError> {
    if seed.len() != 32 || public_key.len() != 32 {
        return fail_msg("ERR_ENCODING", "Ed25519 key must be 32 bytes");
    }
    let mut body = vec![0u8; 1 + 4 + 1 + 32 + 1 + 32 + 2];
    body[0] = 4;
    body[1] = ((created_at_unix >> 24) & 0xff) as u8;
    body[2] = ((created_at_unix >> 16) & 0xff) as u8;
    body[3] = ((created_at_unix >> 8) & 0xff) as u8;
    body[4] = (created_at_unix & 0xff) as u8;
    body[5] = 27;
    body[6..38].copy_from_slice(public_key);
    body[38] = 0;
    body[39..71].copy_from_slice(seed);
    let mut sum: u16 = 0;
    for &b in seed {
        sum = sum.wrapping_add(b as u16);
    }
    body[71] = ((sum >> 8) & 0xff) as u8;
    body[72] = (sum & 0xff) as u8;
    Ok(encode_new_format_packet(5, &body))
}

pub fn build_openpgp_ed25519_public(
    public_key: &[u8],
    created_at_unix: u32,
) -> Result<Vec<u8>, CkvfError> {
    if public_key.len() != 32 {
        return fail_msg("ERR_ENCODING", "Ed25519 public key must be 32 bytes");
    }
    let mut body = vec![0u8; 1 + 4 + 1 + 32];
    body[0] = 4;
    body[1] = ((created_at_unix >> 24) & 0xff) as u8;
    body[2] = ((created_at_unix >> 16) & 0xff) as u8;
    body[3] = ((created_at_unix >> 8) & 0xff) as u8;
    body[4] = (created_at_unix & 0xff) as u8;
    body[5] = 27;
    body[6..38].copy_from_slice(public_key);
    Ok(encode_new_format_packet(6, &body))
}
