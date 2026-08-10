//! eas-attestor — publish TEE-attested data to the Ethereum Attestation Service on any EVM chain.
//!
//! Reads a JSON job on stdin, collects on-chain data through an RPC quorum inside the enclave,
//! ABI-encodes it against a user-defined EAS schema, signs an EIP-1559 `attest` transaction with
//! a private key that never leaves the TEE, and broadcasts it. The DCAP attestation of this worker
//! (workers.outlayer.ai) proves that exactly this code produced the on-chain attestation.
//!
//! Modes:
//!   "attest"          collect -> encode -> sign -> broadcast an EAS attestation
//!   "register_schema" register a new schema in the SchemaRegistry (one-time), returns its UID
//!   "dry_run"         collect + build calldata and an unsigned tx preview, broadcast nothing
//!
//! Contract addresses (`chain.eas`, `chain.schema_registry`) are inputs, never hardcoded — the
//! target network is a parameter. `chain.rpcs` must list several independent providers.

mod abi;
mod eas;
mod evm;
mod keccak;
mod rpc;
mod sign;

use abi::{hex_to_array20, hex_to_array32, to_hex_0x};
use eas::{AttestationRequest, Raw};
use serde_json::{json, Value};
use sign::{Eip1559Tx, Signer};
use std::collections::HashMap;
use std::io::Read;

fn main() {
    let out = match run() {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "error": e }),
    };
    println!("{}", out);
}

fn run() -> Result<Value, String> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("reading stdin: {}", e))?;
    let cfg: Value = serde_json::from_str(input.trim())
        .map_err(|e| format!("input is not valid JSON: {}", e))?;

    let mode = cfg.get("mode").and_then(|v| v.as_str()).unwrap_or("attest");
    // `chain.network` (e.g. "base", "base-sepolia") fills in EAS/registry addresses, chain_id and
    // default public RPCs for any field not given explicitly — pick a testnet to try it gas-free.
    let chain_owned = effective_chain(cfg.get("chain").ok_or("missing \"chain\"")?)?;
    let chain = &chain_owned;
    let rpcs = resolve_rpcs(&string_array(chain, "rpcs")?)?;
    if rpcs.is_empty() {
        return Err("chain.rpcs must list at least one RPC (several for a real quorum)".into());
    }

    match mode {
        "register_schema" => register_schema(&cfg, chain, &rpcs),
        "attest" | "dry_run" => attest(&cfg, chain, &rpcs, mode == "dry_run"),
        other => Err(format!("unknown mode: {}", other)),
    }
}

fn attest(cfg: &Value, chain: &Value, rpcs: &[String], dry_run: bool) -> Result<Value, String> {
    let schema = cfg.get("schema").ok_or("missing \"schema\"")?;
    let definition = schema
        .get("definition")
        .and_then(|v| v.as_str())
        .ok_or("schema.definition is required (e.g. \"uint256 locked,uint256 minted\")")?;
    let fields = eas::parse_schema(definition)?;

    // Collect each value at a pinned, quorum-agreed block. A collector may carry its own `rpcs`
    // (and `min_agree`/`blocks_behind`/`chain_id`) — that is how one attestation aggregates data
    // from several chains (e.g. locked-on-Ethereum vs minted-on-Base). Missing fields fall back to
    // the top-level chain. Each distinct (rpcs, blocks_behind) is pinned to its own recent block.
    let default_bb = cfg.get("blocks_behind").and_then(|v| v.as_u64()).unwrap_or(4);
    let default_min = cfg.get("min_agree").and_then(|v| v.as_u64()).unwrap_or(2) as usize;

    let collect_items = cfg
        .get("collect")
        .and_then(|v| v.as_array())
        .ok_or("missing \"collect\" array")?;
    if collect_items.len() != fields.len() {
        return Err(format!(
            "schema has {} fields but collect has {} items — they map one-to-one, in order",
            fields.len(),
            collect_items.len()
        ));
    }

    let mut block_cache: HashMap<String, u64> = HashMap::new();
    let primary_block = block_for(&mut block_cache, rpcs, default_bb)?;

    let mut values: Vec<Raw> = Vec::new();
    let mut evidence: Vec<Value> = Vec::new();
    for (item, field) in collect_items.iter().zip(fields.iter()) {
        let item_rpcs = if item.get("rpcs").is_some() {
            resolve_rpcs(&string_array(item, "rpcs")?)?
        } else {
            rpcs.to_vec()
        };
        if item_rpcs.is_empty() {
            return Err(format!("collect field {:?} has an empty rpcs list", field.name));
        }
        let bb = item.get("blocks_behind").and_then(|v| v.as_u64()).unwrap_or(default_bb);
        let ma = item.get("min_agree").and_then(|v| v.as_u64()).unwrap_or(default_min as u64) as usize;
        let block = block_for(&mut block_cache, &item_rpcs, bb)?;

        let src = evm::Source::from_json(item)?;
        let c = evm::collect(&src, &item_rpcs, block, ma)?;
        values.push(c.raw);
        let mut ev = c.evidence;
        ev["field"] = json!(field.name);
        ev["type"] = json!(field.ty);
        ev["block"] = json!(block);
        if let Some(cid) = item.get("chain_id").and_then(|v| v.as_u64()) {
            ev["chain_id"] = json!(cid);
        }
        evidence.push(ev);
    }

    let data = eas::encode_schema_data(&fields, &values)?;

    // A real attestation needs the on-chain schema UID; a dry run just previews, so default to zero.
    let schema_uid = match schema.get("uid").and_then(|v| v.as_str()) {
        Some(s) if !(s == "0x0" || s.is_empty()) => hex_to_array32(s)?,
        _ if dry_run => [0u8; 32],
        _ => return Err("schema.uid is required for attest (register the schema first)".into()),
    };
    let req = AttestationRequest {
        schema_uid,
        recipient: opt_addr(schema, "recipient")?,
        expiration_time: schema.get("expiration").and_then(|v| v.as_u64()).unwrap_or(0),
        revocable: schema.get("revocable").and_then(|v| v.as_bool()).unwrap_or(true),
        ref_uid: opt_bytes32(schema, "ref_uid")?,
        data: data.clone(),
        value: 0,
    };
    let eas_addr = hex_to_array20(
        chain.get("eas").and_then(|v| v.as_str()).ok_or("chain.eas address is required")?,
    )?;
    let calldata = req.calldata();

    let base = json!({
        "mode": if dry_run { "dry_run" } else { "attest" },
        "block_number": primary_block,
        "schema_uid": to_hex_0x(&req.schema_uid),
        "attestation_data": to_hex_0x(&data),
        "calldata": to_hex_0x(&calldata),
        "collected": evidence,
    });

    // Signing key is only needed to actually send (or to show the attester in a dry run).
    let signer = load_signer(cfg).ok();
    if dry_run {
        let mut v = base;
        v["success"] = json!(true);
        v["eas"] = json!(to_hex_0x(&eas_addr));
        if let Some(s) = &signer {
            v["attester"] = json!(to_hex_0x(&s.address));
        }
        return Ok(v);
    }

    let signer = signer.ok_or("attest mode needs a signing key (set key_env to a funded secret)")?;
    let sent = send_tx(cfg, chain, rpcs, &signer, &eas_addr, &calldata)?;

    let mut v = base;
    v["success"] = json!(true);
    v["attester"] = json!(to_hex_0x(&signer.address));
    v["tx_hash"] = json!(sent.tx_hash);
    v["nonce"] = json!(sent.nonce);
    if let Some(url) = easscan_address_url(&cfg_chain_id(cfg, chain, rpcs)?, &signer.address) {
        v["attester_url"] = json!(url);
    }
    Ok(v)
}

fn register_schema(cfg: &Value, chain: &Value, rpcs: &[String]) -> Result<Value, String> {
    let schema = cfg.get("schema").ok_or("missing \"schema\"")?;
    let definition = schema
        .get("definition")
        .and_then(|v| v.as_str())
        .ok_or("schema.definition is required")?;
    let resolver = opt_addr(schema, "resolver")?;
    let revocable = schema.get("revocable").and_then(|v| v.as_bool()).unwrap_or(true);

    let registry = hex_to_array20(
        chain
            .get("schema_registry")
            .and_then(|v| v.as_str())
            .ok_or("chain.schema_registry address is required")?,
    )?;
    let calldata = eas::register_schema_calldata(definition, resolver, revocable);
    let predicted_uid = predicted_schema_uid(definition, &resolver, revocable);

    let signer = load_signer(cfg)?;
    let sent = send_tx(cfg, chain, rpcs, &signer, &registry, &calldata)?;
    Ok(json!({
        "success": true,
        "mode": "register_schema",
        "registrant": to_hex_0x(&signer.address),
        "definition": definition,
        "predicted_schema_uid": to_hex_0x(&predicted_uid),
        "tx_hash": sent.tx_hash,
        "nonce": sent.nonce,
    }))
}

struct Sent {
    tx_hash: String,
    nonce: u64,
}

fn send_tx(
    cfg: &Value,
    chain: &Value,
    rpcs: &[String],
    signer: &Signer,
    to: &[u8; 20],
    data: &[u8],
) -> Result<Sent, String> {
    let chain_id = cfg_chain_id(cfg, chain, rpcs)?;
    let nonce = rpc::pending_nonce(rpcs, &signer.address)?;
    let (base_fee, mut priority) = rpc::fees(rpcs)?;
    if let Some(p) = cfg.get("max_priority_fee_wei").and_then(|v| v.as_u64()) {
        priority = p as u128;
    }
    let max_fee = base_fee.saturating_mul(2).saturating_add(priority);

    let gas_limit = match cfg.get("gas_limit").and_then(|v| v.as_u64()) {
        Some(g) => g,
        None => {
            let est = rpc::estimate_gas(rpcs, &signer.address, to, data)?;
            est.saturating_mul(125) / 100 // +25% headroom
        }
    };

    let tx = Eip1559Tx {
        chain_id,
        nonce,
        max_priority_fee: priority,
        max_fee,
        gas_limit,
        to: *to,
        value: 0,
        data: data.to_vec(),
    };
    let raw = tx.sign(signer)?;
    let tx_hash = rpc::send_raw(rpcs, &raw)?;
    Ok(Sent { tx_hash, nonce })
}

// ---- helpers ---------------------------------------------------------------

fn load_signer(cfg: &Value) -> Result<Signer, String> {
    let key_env = cfg
        .get("key_env")
        .and_then(|v| v.as_str())
        .unwrap_or("PROTECTED_EAS_KEY");
    let pk = std::env::var(key_env)
        .map_err(|_| format!("secret env var {:?} is not set for this execution", key_env))?;
    Signer::from_hex(&pk)
}

fn cfg_chain_id(cfg: &Value, chain: &Value, rpcs: &[String]) -> Result<u64, String> {
    if let Some(id) = chain.get("chain_id").and_then(|v| v.as_u64()) {
        return Ok(id);
    }
    let _ = cfg;
    rpc::chain_id(rpcs)
}

/// Cached "recent block" per (rpc-set, blocks_behind), so several same-chain collectors pin the
/// same block and we make one eth_blockNumber round per distinct chain.
fn block_for(
    cache: &mut HashMap<String, u64>,
    rpcs: &[String],
    blocks_behind: u64,
) -> Result<u64, String> {
    let key = format!("{}|{}", rpcs.join(","), blocks_behind);
    if let Some(b) = cache.get(&key) {
        return Ok(*b);
    }
    let b = rpc::block_number_behind_head(rpcs, blocks_behind)?;
    cache.insert(key, b);
    Ok(b)
}

/// Substitute `${SECRET_NAME}` in an RPC URL with an injected secret (e.g. a provider API key baked
/// into the URL). The secret arrives as an env var, same as any OutLayer secret.
fn resolve_secrets(url: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = url;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| format!("unterminated ${{...}} in RPC URL: {}", url))?;
        let name = &after[..end];
        let val = std::env::var(name)
            .map_err(|_| format!("RPC URL references secret {:?} which is not set", name))?;
        out.push_str(&val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve_rpcs(rpcs: &[String]) -> Result<Vec<String>, String> {
    rpcs.iter().map(|r| resolve_secrets(r)).collect()
}

struct Net {
    chain_id: u64,
    eas: &'static str,
    registry: &'static str,
    rpcs: &'static [&'static str],
}

/// Convenience presets so `chain.network` alone is enough to target a chain. All EAS/registry
/// addresses verified against the official eas-contracts deployments (2026-08-08). RPCs are public
/// endpoints and can be overridden with an explicit `chain.rpcs`.
fn network_defaults(name: &str) -> Option<Net> {
    Some(match name {
        "base" => Net {
            chain_id: 8453,
            eas: "0x4200000000000000000000000000000000000021",
            registry: "0x4200000000000000000000000000000000000020",
            rpcs: &["https://mainnet.base.org", "https://base.llamarpc.com", "https://base.drpc.org"],
        },
        "base-sepolia" => Net {
            chain_id: 84532,
            eas: "0x4200000000000000000000000000000000000021",
            registry: "0x4200000000000000000000000000000000000020",
            rpcs: &[
                "https://sepolia.base.org",
                "https://base-sepolia-rpc.publicnode.com",
                "https://base-sepolia.drpc.org",
            ],
        },
        "optimism" => Net {
            chain_id: 10,
            eas: "0x4200000000000000000000000000000000000021",
            registry: "0x4200000000000000000000000000000000000020",
            rpcs: &["https://mainnet.optimism.io", "https://optimism.drpc.org", "https://optimism.llamarpc.com"],
        },
        "arbitrum" => Net {
            chain_id: 42161,
            eas: "0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458",
            registry: "0xA310da9c5B885E7fb3fbA9D66E9Ba6Df512b78eB",
            rpcs: &["https://arb1.arbitrum.io/rpc", "https://arbitrum.drpc.org", "https://arbitrum.llamarpc.com"],
        },
        "ethereum" => Net {
            chain_id: 1,
            eas: "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
            registry: "0xA7b39296258348C78294F95B872b282326A97BDF",
            rpcs: &["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://rpc.mevblocker.io"],
        },
        "sepolia" => Net {
            chain_id: 11155111,
            eas: "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",
            registry: "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
            rpcs: &[
                "https://ethereum-sepolia-rpc.publicnode.com",
                "https://sepolia.drpc.org",
                "https://1rpc.io/sepolia",
            ],
        },
        _ => return None,
    })
}

/// Apply `chain.network` presets to any field the caller did not set explicitly.
fn effective_chain(chain: &Value) -> Result<Value, String> {
    let mut c = chain.clone();
    if let Some(net_name) = chain.get("network").and_then(|v| v.as_str()) {
        let d = network_defaults(net_name).ok_or_else(|| {
            format!(
                "unknown network {:?}; known: base, base-sepolia, optimism, arbitrum, ethereum, sepolia",
                net_name
            )
        })?;
        let obj = c.as_object_mut().ok_or("chain must be an object")?;
        obj.entry("chain_id").or_insert(json!(d.chain_id));
        obj.entry("eas").or_insert(json!(d.eas));
        obj.entry("schema_registry").or_insert(json!(d.registry));
        if !obj.contains_key("rpcs") {
            obj.insert("rpcs".to_string(), json!(d.rpcs));
        }
    }
    Ok(c)
}

fn string_array(v: &Value, key: &str) -> Result<Vec<String>, String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| format!("{} must be an array", key))
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                .collect()
        })
}

fn opt_addr(v: &Value, key: &str) -> Result<[u8; 20], String> {
    match v.get(key).and_then(|x| x.as_str()) {
        None => Ok([0u8; 20]),
        Some(s) if s == "0x0" || s.is_empty() => Ok([0u8; 20]),
        Some(s) => hex_to_array20(s),
    }
}

fn opt_bytes32(v: &Value, key: &str) -> Result<[u8; 32], String> {
    match v.get(key).and_then(|x| x.as_str()) {
        None => Ok([0u8; 32]),
        Some(s) if s == "0x0" || s.is_empty() => Ok([0u8; 32]),
        Some(s) => hex_to_array32(s),
    }
}

/// EAS SchemaRegistry UID = keccak256(abi.encodePacked(schema, resolver, revocable)).
fn predicted_schema_uid(definition: &str, resolver: &[u8; 20], revocable: bool) -> [u8; 32] {
    let mut packed = Vec::new();
    packed.extend_from_slice(definition.as_bytes());
    packed.extend_from_slice(resolver);
    packed.push(revocable as u8);
    keccak::keccak256(&packed)
}

/// Public EAS explorer domains, for convenience links only. Contract addresses always come from
/// input; this map is UI sugar and is intentionally small (extend as chains are confirmed).
fn easscan_address_url(chain_id: &u64, address: &[u8; 20]) -> Option<String> {
    let domain = match chain_id {
        1 => "easscan.org",
        11155111 => "sepolia.easscan.org",
        8453 => "base.easscan.org",
        84532 => "base-sepolia.easscan.org",
        42161 => "arbitrum.easscan.org",
        10 => "optimism.easscan.org",
        _ => return None,
    };
    Some(format!("https://{}/address/{}", domain, to_hex_0x(address)))
}
