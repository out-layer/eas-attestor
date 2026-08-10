//! secp256k1 signing done *inside the enclave* with k256, plus EIP-1559 transaction encoding.
//!
//! The private key arrives as an env-var secret (decrypted in the TEE worker, injected by name)
//! and never leaves this process. The attester address is derived from it, so consumers can see
//! on-chain exactly which key signed — and the DCAP attestation proves this code did the signing.

use crate::abi::hex_to_bytes;
use crate::keccak::keccak256;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use rlp::RlpStream;

pub struct Signer {
    sk: SigningKey,
    pub address: [u8; 20],
}

impl Signer {
    /// Build from a 32-byte hex private key (with or without `0x`).
    pub fn from_hex(pk_hex: &str) -> Result<Self, String> {
        let bytes = hex_to_bytes(pk_hex.trim())?;
        if bytes.len() != 32 {
            return Err(format!("private key must be 32 bytes, got {}", bytes.len()));
        }
        let sk = SigningKey::from_slice(&bytes).map_err(|e| format!("invalid private key: {}", e))?;
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false); // 0x04 || X(32) || Y(32)
        let pub_bytes = point.as_bytes();
        let h = keccak256(&pub_bytes[1..]); // hash of X||Y
        let mut address = [0u8; 20];
        address.copy_from_slice(&h[12..]);
        Ok(Signer { sk, address })
    }

    /// Sign a 32-byte prehash. Returns (yParity 0/1, r, s), low-S normalized by k256.
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<(u8, [u8; 32], [u8; 32]), String> {
        let (sig, recid): (Signature, RecoveryId) = self
            .sk
            .sign_prehash_recoverable(hash)
            .map_err(|e| format!("signing failed: {}", e))?;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig.r().to_bytes());
        s.copy_from_slice(&sig.s().to_bytes());
        Ok((recid.to_byte(), r, s))
    }
}

/// An EIP-1559 (type-0x02) transaction, all amounts in wei.
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
}

/// Minimal big-endian encoding of an integer (RLP scalar form: no leading zeros; 0 -> empty).
fn min_be(v: u128) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

fn trim_left(bytes: &[u8]) -> Vec<u8> {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

impl Eip1559Tx {
    /// The 9 base fields, in order, appended to an existing list stream.
    fn append_base(&self, s: &mut RlpStream) {
        s.append(&min_be(self.chain_id as u128));
        s.append(&min_be(self.nonce as u128));
        s.append(&min_be(self.max_priority_fee));
        s.append(&min_be(self.max_fee));
        s.append(&min_be(self.gas_limit as u128));
        s.append(&self.to.to_vec());
        s.append(&min_be(self.value));
        s.append(&self.data);
        s.begin_list(0); // empty access list
    }

    /// keccak256(0x02 || rlp([9 base fields])) — the hash the signer signs.
    pub fn sighash(&self) -> [u8; 32] {
        let mut s = RlpStream::new_list(9);
        self.append_base(&mut s);
        let mut payload = vec![0x02u8];
        payload.extend_from_slice(&s.out());
        keccak256(&payload)
    }

    /// Sign and return the raw `0x02…`-prefixed transaction bytes, ready for eth_sendRawTransaction.
    pub fn sign(&self, signer: &Signer) -> Result<Vec<u8>, String> {
        let (y_parity, r, s_val) = signer.sign_hash(&self.sighash())?;

        let mut s = RlpStream::new_list(12);
        self.append_base(&mut s);
        s.append(&min_be(y_parity as u128));
        s.append(&trim_left(&r));
        s.append(&trim_left(&s_val));

        let mut raw = vec![0x02u8];
        raw.extend_from_slice(&s.out());
        Ok(raw)
    }
}
