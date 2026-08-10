//! EAS calldata: register a schema, and attest under one. Schema-field encoding lives here too.

use crate::abi::{self, Val};

/// EAS `attest((bytes32 schema,(address recipient,uint64 expirationTime,bool revocable,
/// bytes32 refUID,bytes data,uint256 value)))`.
pub const ATTEST_SIG: &str =
    "attest((bytes32,(address,uint64,bool,bytes32,bytes,uint256)))";

/// SchemaRegistry `register(string schema,address resolver,bool revocable)`.
pub const REGISTER_SIG: &str = "register(string,address,bool)";

pub struct AttestationRequest {
    pub schema_uid: [u8; 32],
    pub recipient: [u8; 20],
    pub expiration_time: u64,
    pub revocable: bool,
    pub ref_uid: [u8; 32],
    /// ABI-encoded schema payload (see `encode_schema_data`).
    pub data: Vec<u8>,
    pub value: u128,
}

impl AttestationRequest {
    pub fn calldata(&self) -> Vec<u8> {
        let inner = Val::Tuple(vec![
            Val::Address(self.recipient),
            Val::uint_u128(self.expiration_time as u128),
            Val::Bool(self.revocable),
            Val::FixedBytes32(self.ref_uid),
            Val::Bytes(self.data.clone()),
            Val::uint_u128(self.value),
        ]);
        let request = Val::Tuple(vec![Val::FixedBytes32(self.schema_uid), inner]);
        abi::call(ATTEST_SIG, &[request])
    }
}

pub fn register_schema_calldata(definition: &str, resolver: [u8; 20], revocable: bool) -> Vec<u8> {
    abi::call(
        REGISTER_SIG,
        &[
            Val::Str(definition.to_string()),
            Val::Address(resolver),
            Val::Bool(revocable),
        ],
    )
}

/// A single field of an EAS schema, e.g. `uint256 locked`. `name` is retained for diagnostics
/// and echoed back to callers so a mis-ordered `collect` list is easy to spot.
pub struct SchemaField {
    pub ty: String,
    pub name: String,
}

/// Parse a schema definition string ("uint256 locked,uint256 minted,uint64 blockNumber")
/// into ordered fields. Whitespace and a trailing comma are tolerated.
pub fn parse_schema(definition: &str) -> Result<Vec<SchemaField>, String> {
    let mut out = Vec::new();
    for part in definition.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut it = part.split_whitespace();
        let ty = it
            .next()
            .ok_or_else(|| format!("schema field has no type: {:?}", part))?;
        let name = it
            .next()
            .ok_or_else(|| format!("schema field has no name: {:?}", part))?;
        out.push(SchemaField {
            ty: ty.to_string(),
            name: name.to_string(),
        });
    }
    if out.is_empty() {
        return Err("schema definition is empty".to_string());
    }
    Ok(out)
}

/// Coerce a collected raw value into the `Val` demanded by a schema field's Solidity type.
/// `raw` is the canonical form each collector produces: big-endian bytes for numerics/bytes32,
/// 20-byte address, or a UTF-8 string for `string`.
pub fn coerce(field_ty: &str, raw: &Raw) -> Result<Val, String> {
    let base = field_ty.trim();
    match base {
        _ if base.starts_with("uint") => match raw {
            Raw::Bytes(be) => Val::uint_be(be),
            Raw::Str(s) => Val::uint_be(&abi::hex_to_bytes(s)?),
            Raw::Address(a) => Val::uint_be(a),
        },
        "address" => match raw {
            Raw::Address(a) => Ok(Val::Address(*a)),
            Raw::Bytes(b) if b.len() == 20 => {
                let mut a = [0u8; 20];
                a.copy_from_slice(b);
                Ok(Val::Address(a))
            }
            Raw::Bytes(b) if b.len() == 32 => {
                let mut a = [0u8; 20];
                a.copy_from_slice(&b[12..]);
                Ok(Val::Address(a))
            }
            _ => Err(format!("cannot coerce {:?} into address", raw)),
        },
        "bool" => match raw {
            Raw::Bytes(b) => Ok(Val::Bool(b.iter().any(|&x| x != 0))),
            _ => Err(format!("cannot coerce {:?} into bool", raw)),
        },
        "bytes32" => match raw {
            Raw::Bytes(b) => Ok(Val::FixedBytes32(abi::hex_to_array32(&abi::to_hex_0x(
                &right_pad32(b),
            ))?)),
            _ => Err(format!("cannot coerce {:?} into bytes32", raw)),
        },
        "string" => match raw {
            Raw::Str(s) => Ok(Val::Str(s.clone())),
            Raw::Bytes(b) => Ok(Val::Str(String::from_utf8_lossy(b).into_owned())),
            _ => Err(format!("cannot coerce {:?} into string", raw)),
        },
        "bytes" => match raw {
            Raw::Bytes(b) => Ok(Val::Bytes(b.clone())),
            Raw::Str(s) => Ok(Val::Bytes(abi::hex_to_bytes(s)?)),
            _ => Err(format!("cannot coerce {:?} into bytes", raw)),
        },
        other => Err(format!("unsupported schema type: {}", other)),
    }
}

fn right_pad32(b: &[u8]) -> [u8; 32] {
    let mut o = [0u8; 32];
    let n = b.len().min(32);
    o[..n].copy_from_slice(&b[..n]);
    o
}

/// Canonical collected value before it is coerced to a schema type.
#[derive(Debug, Clone)]
pub enum Raw {
    Bytes(Vec<u8>),
    Address([u8; 20]),
    /// Produced by string-valued collectors (e.g. an HTTP/JSON field in a future preset).
    #[allow(dead_code)]
    Str(String),
}

/// ABI-encode collected values against the parsed schema, field by field.
pub fn encode_schema_data(fields: &[SchemaField], values: &[Raw]) -> Result<Vec<u8>, String> {
    if fields.len() != values.len() {
        return Err(format!(
            "schema has {} fields but {} values were collected",
            fields.len(),
            values.len()
        ));
    }
    let mut vals = Vec::with_capacity(fields.len());
    for (f, v) in fields.iter().zip(values.iter()) {
        vals.push(coerce(&f.ty, v)?);
    }
    Ok(abi::encode(&vals))
}
