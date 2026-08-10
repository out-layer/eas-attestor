//! JSON-RPC over HTTP, with a quorum layer for the reads that must be trustworthy.
//!
//! Data that ends up in an attestation (balances, call results) is read from several independent
//! RPCs pinned to the same block; if they do not return a byte-identical answer we refuse rather
//! than attest a number one node could have fabricated. Transaction plumbing (nonce, fees, send)
//! does not need that — a wrong nonce or fee just makes the tx fail, it cannot corrupt the data.

use serde_json::{json, Value};
use std::time::Duration;
use wasi_http_client::Client;

pub const USER_AGENT: &str = "eas-attestor/0.1 (+https://outlayer.ai)";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn post(rpc_url: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

    let response = Client::new()
        .post(rpc_url)
        .header("User-Agent", USER_AGENT)
        .header("Content-Type", "application/json")
        .connect_timeout(CONNECT_TIMEOUT)
        .body(&body_bytes)
        .send()
        .map_err(|e| format!("{}: {}", rpc_url, e))?;

    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(format!("{}: HTTP {}", rpc_url, status));
    }
    let raw = response.body().map_err(|e| format!("{}: {}", rpc_url, e))?;
    let parsed: Value =
        serde_json::from_slice(&raw).map_err(|e| format!("{}: malformed JSON: {}", rpc_url, e))?;
    if let Some(err) = parsed.get("error") {
        return Err(format!("{}: RPC error: {}", rpc_url, err));
    }
    parsed
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{}: response had no result", rpc_url))
}

/// Highest block number seen across the RPCs, minus a margin so honest nodes have converged.
pub fn block_number_behind_head(rpcs: &[String], behind: u64) -> Result<u64, String> {
    let mut best: Option<u64> = None;
    let mut errors = Vec::new();
    for rpc in rpcs {
        match post(rpc, "eth_blockNumber", json!([])) {
            Ok(v) => match parse_u64_hex(&v) {
                Ok(n) => best = Some(best.map_or(n, |b| b.max(n))),
                Err(e) => errors.push(format!("{}: {}", rpc, e)),
            },
            Err(e) => errors.push(e),
        }
    }
    best.map(|n| n.saturating_sub(behind))
        .ok_or_else(|| format!("no RPC returned a block number: {}", errors.join("; ")))
}

/// Run an eth_call (or eth_getBalance) at a pinned block across all RPCs and require agreement.
///
/// `method` is "eth_call" or "eth_getBalance"; `params_head` is everything before the block tag.
/// Returns the agreed raw hex result and the list of RPCs that vouched for it.
pub fn quorum_read(
    rpcs: &[String],
    method: &str,
    params_head: Value,
    block_number: u64,
    min_agree: usize,
) -> Result<(String, Vec<String>), String> {
    let tag = format!("0x{:x}", block_number);
    let mut params = params_head.as_array().cloned().unwrap_or_default();
    params.push(json!(tag));
    let params = Value::Array(params);

    let mut answers: Vec<(String, String)> = Vec::new(); // (rpc, result-hex)
    let mut rejected = Vec::new();
    for rpc in rpcs {
        match post(rpc, method, params.clone()) {
            Ok(v) => match v.as_str() {
                Some(s) => answers.push((rpc.clone(), s.to_lowercase())),
                None => rejected.push(format!("{}: non-string result {}", rpc, v)),
            },
            Err(e) => rejected.push(e),
        }
    }

    // Keep the answer the most RPCs agree on.
    let mut best: Option<(String, Vec<String>)> = None;
    for (_, res) in &answers {
        let backers: Vec<String> = answers
            .iter()
            .filter(|(_, r)| r == res)
            .map(|(rpc, _)| rpc.clone())
            .collect();
        if best.as_ref().map_or(true, |(_, b)| backers.len() > b.len()) {
            best = Some((res.clone(), backers));
        }
    }
    let (result, agreed_by) = best.ok_or_else(|| {
        format!(
            "no RPC returned a usable {} result: {}",
            method,
            rejected.join("; ")
        )
    })?;

    if agreed_by.len() < min_agree {
        let others: Vec<String> = answers
            .iter()
            .filter(|(rpc, _)| !agreed_by.contains(rpc))
            .map(|(rpc, r)| format!("{} said {}", rpc, r))
            .collect();
        return Err(format!(
            "only {} of {} RPCs agreed on {} at block {} (needed {}). Disagreed: {}. Unusable: {}",
            agreed_by.len(),
            rpcs.len(),
            method,
            block_number,
            min_agree,
            if others.is_empty() { "none".into() } else { others.join("; ") },
            if rejected.is_empty() { "none".into() } else { rejected.join("; ") },
        ));
    }
    Ok((result, agreed_by))
}

// ---- transaction plumbing (single responsive RPC is fine) ------------------

fn first_ok<T>(
    rpcs: &[String],
    mut f: impl FnMut(&str) -> Result<T, String>,
) -> Result<T, String> {
    let mut errors = Vec::new();
    for rpc in rpcs {
        match f(rpc) {
            Ok(v) => return Ok(v),
            Err(e) => errors.push(e),
        }
    }
    Err(errors.join("; "))
}

pub fn chain_id(rpcs: &[String]) -> Result<u64, String> {
    first_ok(rpcs, |rpc| {
        post(rpc, "eth_chainId", json!([])).and_then(|v| parse_u64_hex(&v))
    })
}

/// Pending nonce for `address` — take the max across RPCs so we never reuse one.
pub fn pending_nonce(rpcs: &[String], address: &[u8; 20]) -> Result<u64, String> {
    let addr = crate::abi::to_hex_0x(address);
    let mut best: Option<u64> = None;
    let mut errors = Vec::new();
    for rpc in rpcs {
        match post(rpc, "eth_getTransactionCount", json!([addr, "pending"])) {
            Ok(v) => match parse_u64_hex(&v) {
                Ok(n) => best = Some(best.map_or(n, |b| b.max(n))),
                Err(e) => errors.push(format!("{}: {}", rpc, e)),
            },
            Err(e) => errors.push(e),
        }
    }
    best.ok_or_else(|| format!("no RPC returned a nonce: {}", errors.join("; ")))
}

/// (base_fee_per_gas, suggested_priority_fee) from the latest block, both in wei.
pub fn fees(rpcs: &[String]) -> Result<(u128, u128), String> {
    let base = first_ok(rpcs, |rpc| {
        let block = post(rpc, "eth_getBlockByNumber", json!(["latest", false]))?;
        block
            .get("baseFeePerGas")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{}: block has no baseFeePerGas", rpc))
            .and_then(|s| parse_u128_hex(s))
    })?;
    // eth_maxPriorityFeePerGas is widely but not universally supported; fall back to 0.05 gwei.
    let priority = first_ok(rpcs, |rpc| {
        post(rpc, "eth_maxPriorityFeePerGas", json!([])).and_then(|v| {
            v.as_str()
                .ok_or_else(|| "non-string".to_string())
                .and_then(parse_u128_hex)
        })
    })
    .unwrap_or(50_000_000);
    Ok((base, priority))
}

pub fn estimate_gas(
    rpcs: &[String],
    from: &[u8; 20],
    to: &[u8; 20],
    data: &[u8],
) -> Result<u64, String> {
    let call = json!({
        "from": crate::abi::to_hex_0x(from),
        "to": crate::abi::to_hex_0x(to),
        "data": crate::abi::to_hex_0x(data),
    });
    first_ok(rpcs, |rpc| {
        post(rpc, "eth_estimateGas", json!([call])).and_then(|v| parse_u64_hex(&v))
    })
}

/// Broadcast to every RPC; succeed if any accepts. Returns the tx hash.
pub fn send_raw(rpcs: &[String], raw: &[u8]) -> Result<String, String> {
    let raw_hex = crate::abi::to_hex_0x(raw);
    let mut hash: Option<String> = None;
    let mut errors = Vec::new();
    for rpc in rpcs {
        match post(rpc, "eth_sendRawTransaction", json!([raw_hex])) {
            Ok(v) => {
                if let Some(h) = v.as_str() {
                    hash = Some(h.to_string());
                }
            }
            Err(e) => errors.push(e),
        }
    }
    hash.ok_or_else(|| format!("no RPC accepted the transaction: {}", errors.join("; ")))
}

pub fn parse_u64_hex(v: &Value) -> Result<u64, String> {
    let s = v.as_str().ok_or_else(|| format!("expected hex string, got {}", v))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| format!("bad hex {}: {}", s, e))
}

pub fn parse_u128_hex(s: &str) -> Result<u128, String> {
    u128::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| format!("bad hex {}: {}", s, e))
}
