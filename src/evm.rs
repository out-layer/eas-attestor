//! Data collectors — the values that end up inside an attestation. Every read goes through the
//! RPC quorum, so a single lying provider cannot change what we attest.

use crate::abi::{self, Val};
use crate::eas::Raw;
use crate::keccak::selector;
use crate::rpc;
use serde_json::{json, Value};

pub enum Source {
    /// ERC-20 `balanceOf(holder)` on `token`.
    Erc20Balance { token: [u8; 20], holder: [u8; 20] },
    /// ERC-20 `totalSupply()` on `token`.
    Erc20TotalSupply { token: [u8; 20] },
    /// Native coin balance of `address`.
    NativeBalance { address: [u8; 20] },
    /// Arbitrary `eth_call` to `to` with `data`; decode the first return word as `returns`.
    EvmCall { to: [u8; 20], data: Vec<u8>, returns: String },
    /// The pinned block number itself — no RPC read, just records which block was attested.
    BlockNumber,
    /// `eth_getCode(address)` — derive a fact about a contract's bytecode.
    /// `report`: "code_hash" (bytes32 keccak of the code), "is_contract" (bool), "code_size" (uint).
    EthCode { address: [u8; 20], report: String },
    /// This execution's own identifier, so the attestation can point at the TEE quote that produced
    /// it. `form`: "call_id" (the bare id) or "url" (the full attestation endpoint).
    TeeAttestation { form: String, api_base: String },
}

pub struct Collected {
    pub raw: Raw,
    pub evidence: Value,
}

impl Source {
    pub fn from_json(v: &Value) -> Result<Source, String> {
        let ty = v
            .get("type")
            .and_then(|x| x.as_str())
            .ok_or("collect item missing \"type\"")?;
        let addr = |key: &str| -> Result<[u8; 20], String> {
            v.get(key)
                .and_then(|x| x.as_str())
                .ok_or_else(|| format!("collect {} missing \"{}\"", ty, key))
                .and_then(abi::hex_to_array20)
        };
        match ty {
            "erc20_balance" => Ok(Source::Erc20Balance {
                token: addr("token")?,
                holder: addr("holder")?,
            }),
            "erc20_total_supply" => Ok(Source::Erc20TotalSupply { token: addr("token")? }),
            "native_balance" => Ok(Source::NativeBalance { address: addr("address")? }),
            "block_number" => Ok(Source::BlockNumber),
            "tee_attestation" => Ok(Source::TeeAttestation {
                form: v
                    .get("returns")
                    .and_then(|x| x.as_str())
                    .unwrap_or("url")
                    .to_string(),
                api_base: v
                    .get("api_base")
                    .and_then(|x| x.as_str())
                    .unwrap_or("https://api.outlayer.ai")
                    .trim_end_matches('/')
                    .to_string(),
            }),
            "eth_code" => Ok(Source::EthCode {
                address: addr("address")?,
                report: v
                    .get("returns")
                    .and_then(|x| x.as_str())
                    .unwrap_or("code_hash")
                    .to_string(),
            }),
            "evm_call" => Ok(Source::EvmCall {
                to: addr("to")?,
                data: abi::hex_to_bytes(
                    v.get("data")
                        .and_then(|x| x.as_str())
                        .ok_or("evm_call missing \"data\"")?,
                )?,
                returns: v
                    .get("returns")
                    .and_then(|x| x.as_str())
                    .unwrap_or("uint256")
                    .to_string(),
            }),
            other => Err(format!("unknown collect type: {}", other)),
        }
    }
}

fn eth_call_word(
    rpcs: &[String],
    to: &[u8; 20],
    data: &[u8],
    block: u64,
    min_agree: usize,
) -> Result<([u8; 32], Vec<String>), String> {
    let call = json!([{ "to": abi::to_hex_0x(to), "data": abi::to_hex_0x(data) }]);
    let (result, agreed) = rpc::quorum_read(rpcs, "eth_call", call, block, min_agree)?;
    let bytes = abi::hex_to_bytes(&result)?;
    if bytes.len() < 32 {
        return Err(format!("eth_call returned {} bytes, expected >= 32", bytes.len()));
    }
    let mut word = [0u8; 32];
    word.copy_from_slice(&bytes[..32]);
    Ok((word, agreed))
}

fn trim_left(b: &[u8]) -> Vec<u8> {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[first..].to_vec()
}

pub fn collect(
    src: &Source,
    rpcs: &[String],
    block: u64,
    min_agree: usize,
) -> Result<Collected, String> {
    match src {
        Source::Erc20Balance { token, holder } => {
            let mut data = selector("balanceOf(address)").to_vec();
            data.extend_from_slice(&abi::encode(&[Val::Address(*holder)]));
            let (word, agreed) = eth_call_word(rpcs, token, &data, block, min_agree)?;
            Ok(Collected {
                raw: Raw::Bytes(trim_left(&word)),
                evidence: json!({
                    "source": "erc20_balance",
                    "token": abi::to_hex_0x(token),
                    "holder": abi::to_hex_0x(holder),
                    "value_hex": abi::to_hex_0x(&word),
                    "agreed_by": agreed,
                }),
            })
        }
        Source::Erc20TotalSupply { token } => {
            let data = selector("totalSupply()").to_vec();
            let (word, agreed) = eth_call_word(rpcs, token, &data, block, min_agree)?;
            Ok(Collected {
                raw: Raw::Bytes(trim_left(&word)),
                evidence: json!({
                    "source": "erc20_total_supply",
                    "token": abi::to_hex_0x(token),
                    "value_hex": abi::to_hex_0x(&word),
                    "agreed_by": agreed,
                }),
            })
        }
        Source::NativeBalance { address } => {
            let (result, agreed) = rpc::quorum_read(
                rpcs,
                "eth_getBalance",
                json!([abi::to_hex_0x(address)]),
                block,
                min_agree,
            )?;
            let be = abi::hex_to_bytes(&result)?;
            Ok(Collected {
                raw: Raw::Bytes(trim_left(&be)),
                evidence: json!({
                    "source": "native_balance",
                    "address": abi::to_hex_0x(address),
                    "value_hex": result,
                    "agreed_by": agreed,
                }),
            })
        }
        Source::BlockNumber => Ok(Collected {
            raw: Raw::Bytes(trim_left(&block.to_be_bytes())),
            evidence: json!({ "source": "block_number", "value": block }),
        }),
        Source::TeeAttestation { form, api_base } => {
            // The platform hands the guest its own execution id: OUTLAYER_CALL_ID over the HTTPS
            // API, NEAR_REQUEST_ID for on-chain requests. Embedding it makes the attestation
            // self-evidencing — a reader can fetch the DCAP quote for the very run that produced
            // these numbers, instead of taking "it ran in a TEE" on faith.
            let call_id = std::env::var("OUTLAYER_CALL_ID").unwrap_or_default();
            let request_id = std::env::var("NEAR_REQUEST_ID").unwrap_or_default();
            let (id, kind) = if !call_id.is_empty() {
                (call_id, "call")
            } else if !request_id.is_empty() {
                (request_id, "request")
            } else {
                return Err("this execution exposed neither OUTLAYER_CALL_ID nor NEAR_REQUEST_ID, so the attestation cannot reference its own TEE quote; drop the tee_attestation source or run it through the OutLayer API".into());
            };
            let url = format!("{}/attestations/by-{}/{}", api_base, kind, id);
            let value = match form.trim() {
                "call_id" => id.clone(),
                "url" => url.clone(),
                other => return Err(format!("tee_attestation returns must be url|call_id, got {}", other)),
            };
            Ok(Collected {
                raw: Raw::Str(value),
                evidence: json!({
                    "source": "tee_attestation",
                    "execution_id": id,
                    "attestation_url": url,
                }),
            })
        }
        Source::EthCode { address, report } => {
            let (result, agreed) = rpc::quorum_read(
                rpcs,
                "eth_getCode",
                json!([abi::to_hex_0x(address)]),
                block,
                min_agree,
            )?;
            let code = abi::hex_to_bytes(&result)?;
            let code_hash = crate::keccak::keccak256(&code);
            let raw = match report.trim() {
                "is_contract" => Raw::Bytes(if code.is_empty() { vec![] } else { vec![1] }),
                "code_size" => Raw::Bytes(trim_left(&(code.len() as u64).to_be_bytes())),
                "code_hash" => Raw::Bytes(code_hash.to_vec()),
                other => return Err(format!("eth_code returns must be code_hash|is_contract|code_size, got {}", other)),
            };
            Ok(Collected {
                raw,
                evidence: json!({
                    "source": "eth_code",
                    "address": abi::to_hex_0x(address),
                    "report": report,
                    "code_size": code.len(),
                    "code_hash": abi::to_hex_0x(&code_hash),
                    "is_contract": !code.is_empty(),
                    "agreed_by": agreed,
                }),
            })
        }
        Source::EvmCall { to, data, returns } => {
            let (word, agreed) = eth_call_word(rpcs, to, data, block, min_agree)?;
            let raw = match returns.trim() {
                "address" => {
                    let mut a = [0u8; 20];
                    a.copy_from_slice(&word[12..]);
                    Raw::Address(a)
                }
                "bytes32" => Raw::Bytes(word.to_vec()),
                _ => Raw::Bytes(trim_left(&word)), // uint*/bool
            };
            Ok(Collected {
                raw,
                evidence: json!({
                    "source": "evm_call",
                    "to": abi::to_hex_0x(to),
                    "returns": returns,
                    "value_hex": abi::to_hex_0x(&word),
                    "agreed_by": agreed,
                }),
            })
        }
    }
}
