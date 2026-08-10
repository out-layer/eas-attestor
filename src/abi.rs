//! A small, exact ABI encoder — only the pieces EAS needs.
//!
//! We deliberately do not pull in a full ABI crate. EAS `attest`/`register` have a fixed,
//! known shape, and the attestation `data` blob is a flat list of typed values. A focused
//! head/tail encoder covers both and is small enough to audit by eye. Correctness is checked
//! against known-good vectors in `tests/` (selectors, an EAS attest calldata, dynamic bytes).

use crate::keccak::selector;

/// One ABI value. Enough types to express every EAS schema field we support in v1.
#[derive(Clone, Debug)]
pub enum Val {
    /// Unsigned integer, given as big-endian bytes (any width up to 32). Left-padded to 32.
    Uint(Vec<u8>),
    Address([u8; 20]),
    Bool(bool),
    FixedBytes32([u8; 32]),
    Bytes(Vec<u8>),
    Str(String),
    /// A struct — encoded inline if all components are static, with an offset if any is dynamic.
    Tuple(Vec<Val>),
}

impl Val {
    /// `uint256`/`uint64`/… from a big-endian slice (leading zeros allowed).
    pub fn uint_be(be: &[u8]) -> Result<Val, String> {
        if be.len() > 32 {
            return Err(format!("uint too wide: {} bytes", be.len()));
        }
        Ok(Val::Uint(be.to_vec()))
    }

    pub fn uint_u128(v: u128) -> Val {
        Val::Uint(v.to_be_bytes().to_vec())
    }
}

fn is_dynamic(v: &Val) -> bool {
    match v {
        Val::Bytes(_) | Val::Str(_) => true,
        Val::Tuple(items) => items.iter().any(is_dynamic),
        _ => false,
    }
}

fn left_pad32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

fn enc_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = left_pad32(&(bytes.len() as u64).to_be_bytes()).to_vec();
    out.extend_from_slice(bytes);
    let pad = (32 - (bytes.len() % 32)) % 32;
    out.extend(std::iter::repeat(0u8).take(pad));
    out
}

/// Full encoding of a single value (its "tail" form).
fn enc(v: &Val) -> Vec<u8> {
    match v {
        Val::Uint(be) => left_pad32(be).to_vec(),
        Val::Address(a) => {
            let mut o = [0u8; 32];
            o[12..].copy_from_slice(a);
            o.to_vec()
        }
        Val::Bool(b) => {
            let mut o = [0u8; 32];
            o[31] = *b as u8;
            o.to_vec()
        }
        Val::FixedBytes32(b) => b.to_vec(),
        Val::Bytes(bytes) => enc_bytes(bytes),
        Val::Str(s) => enc_bytes(s.as_bytes()),
        Val::Tuple(items) => encode(items),
    }
}

/// Encode an ordered list of values as an ABI head/tail region (also the encoding of a tuple).
pub fn encode(items: &[Val]) -> Vec<u8> {
    let head_len: usize = items
        .iter()
        .map(|it| if is_dynamic(it) { 32 } else { enc(it).len() })
        .sum();

    let mut head = Vec::new();
    let mut tail = Vec::new();
    for it in items {
        if is_dynamic(it) {
            let offset = head_len + tail.len();
            head.extend_from_slice(&left_pad32(&(offset as u64).to_be_bytes()));
            tail.extend_from_slice(&enc(it));
        } else {
            head.extend_from_slice(&enc(it));
        }
    }
    head.extend_from_slice(&tail);
    head
}

/// `selector(sig)` followed by the ABI encoding of `args`.
pub fn call(signature: &str, args: &[Val]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    out.extend_from_slice(&encode(args));
    out
}

// ---- hex helpers -----------------------------------------------------------

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("bad hex {:?}: {}", s, e))
}

pub fn hex_to_array20(s: &str) -> Result<[u8; 20], String> {
    let b = hex_to_bytes(s)?;
    if b.len() != 20 {
        return Err(format!("expected 20-byte address, got {} bytes", b.len()));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    Ok(a)
}

pub fn hex_to_array32(s: &str) -> Result<[u8; 32], String> {
    let b = hex_to_bytes(s)?;
    if b.len() != 32 {
        return Err(format!("expected 32 bytes, got {} bytes", b.len()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}

pub fn to_hex_0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
