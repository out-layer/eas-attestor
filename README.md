# eas-attestor

Publish **TEE-attested data to the [Ethereum Attestation Service](https://attest.org) (EAS)** on any
EVM chain. A WASI job runs inside an Intel TDX enclave on OutLayer, reads on-chain data through an
independent-RPC quorum, ABI-encodes it against a user-defined EAS schema, signs an EIP-1559 `attest`
transaction with a key that never leaves the enclave, and broadcasts it.

The differentiator: EAS answers *"who signed this"*, but not *"can I trust how they got the number."*
A TEE upgrades an attester from *"trust this key"* to *"this exact open-source code fetched this data
and signed it"* — provable by the worker's public DCAP attestation at
[workers.outlayer.ai](https://workers.outlayer.ai).

[OutLayer](https://outlayer.ai) · [Documentation](https://app.outlayer.ai/docs) ·
[Verify the enclaves](https://workers.outlayer.ai) · [Deployment guide](DEPLOYMENT.md) ·
[Web form](web/)

## What it does

- **Reads EVM state through a quorum.** Every value that ends up in an attestation is fetched from
  several independent RPCs, pinned to the same block. If they disagree, the job refuses rather than
  attest a number a single node could fabricate. (Transaction plumbing — nonce, fees, broadcast —
  does not need a quorum; a wrong nonce only makes a tx fail, it cannot corrupt the data.)
- **Encodes against your schema.** You define an ordinary EAS schema
  (`uint256 locked,uint256 minted,uint64 blockNumber`); the job maps your collected values to those
  fields in order and ABI-encodes them exactly as EAS expects.
- **Signs inside the TEE.** secp256k1 signing is done in-enclave with `k256`. The attester address
  is derived from the key, so consumers see on-chain precisely which key attested — and the DCAP
  attestation proves this code held it.
- **Targets any EVM chain.** Base, Arbitrum, Ethereum, Optimism, … — the chain, its RPCs and the EAS
  contract addresses are all inputs. Nothing is hardcoded.

## Two ways to run it

1. **Sponsored, via the OutLayer site.** You pay only **gas on the target chain** (the attester key
   you provide must hold a little ETH there). OutLayer sponsors the *report* — the enclave execution
   that collects and signs the data — using its own payment key. You configure what to attest.
2. **Local / your own payment key.** Call the OutLayer HTTPS API with your own payment key and your
   own attester secret. You pay both the OutLayer execution and the chain gas.

In both cases the **attester private key** is supplied as an encrypted secret (see *Secrets*), the
enclave decrypts it only in TEE memory, and it signs the on-chain tx.

## Input

JSON on stdin. Three modes: `attest` (default), `dry_run`, `register_schema`.

```jsonc
{
  "mode": "attest",                        // "attest" | "dry_run" | "register_schema"
  "chain": {
    "network": "base",                     // preset: fills eas/registry/chain_id/rpcs (see Networks)
    "chain_id": 8453,                      // optional; fetched via eth_chainId if omitted
    "rpcs": ["https://rpc1", "https://rpc2", "https://rpc3"],  // several independent providers
    "eas": "0x<EAS contract>",             // required for attest (a network preset fills this)
    "schema_registry": "0x<SchemaRegistry>" // required for register_schema (preset fills this)
  },
  "key_env": "PROTECTED_EAS_KEY",          // secret env var holding the 32-byte attester private key
  "schema": {
    "uid": "0x<schema UID>",               // required for attest (register the schema first)
    "definition": "uint256 locked,uint256 minted,uint64 blockNumber",
    "recipient": "0x0",                    // optional attestation subject (default: zero address)
    "revocable": true,
    "ref_uid": "0x0",
    "expiration": 0
  },
  "collect": [                             // one entry per schema field, SAME ORDER as definition
    { "type": "erc20_balance", "token": "0x<erc20>", "holder": "0x<vault/bridge>" },
    // a collector may target a DIFFERENT chain — this is how one attestation aggregates
    // cross-chain data (e.g. locked-on-Ethereum vs minted-on-Base):
    { "type": "erc20_total_supply", "token": "0x<wrapped token>",
      "chain_id": 1,
      "rpcs": ["https://eth-rpc-1", "https://eth-rpc-2"] },
    { "type": "evm_call", "to": "0x<contract>", "data": "0x<calldata>", "returns": "uint64" }
  ],
  "min_agree": 2,                          // RPCs that must return an identical value (default 2)
  "blocks_behind": 4,                      // pin this many blocks behind head (default 4)
  "max_priority_fee_wei": null,            // optional override
  "gas_limit": null                        // optional override; otherwise estimated + 25%
}
```

### Collectors (`collect[].type`)

| type | reads | fields |
|------|-------|--------|
| `erc20_balance` | `balanceOf(holder)` on an ERC-20 | `token`, `holder` |
| `erc20_total_supply` | `totalSupply()` on an ERC-20 | `token` |
| `native_balance` | native coin balance | `address` |
| `evm_call` | arbitrary `eth_call`, first return word decoded | `to`, `data`, `returns` (`uint256`\|`address`\|`bool`\|`bytes32`) |
| `eth_code` | `eth_getCode`, derives a bytecode fact | `address`, `returns` (`code_hash`\|`is_contract`\|`code_size`) |
| `block_number` | the pinned block number (no RPC read) | — |
| `tee_attestation` | this run's own TEE quote reference | `returns` (`url`\|`call_id`), `api_base` |

### Making the attestation prove its own provenance

`tee_attestation` is the collector that closes the trust loop. The platform records an Intel TDX
quote per execution and exposes it at `/attestations/by-call/{call_id}`; the running job knows its
own execution id, so it can write that reference into the attestation itself (as a `string` field).

Without it, a reader of `base.easscan.org` sees an ordinary EOA and has to take "this ran in a TEE"
on faith. With it, they can fetch the quote for the exact run that produced the numbers. Add a
`string` field to your schema and point a `tee_attestation` source at it.

**Per-collector overrides.** Any collector may carry its own `rpcs`, `chain_id`, `min_agree`, and
`blocks_behind`; anything omitted falls back to the top-level `chain`. Each distinct RPC set is
pinned to its own recent block, and the per-source block is recorded in the output evidence. The
attestation itself is always signed and broadcast on the top-level `chain`.

**Secrets in RPC URLs.** Any RPC URL (top-level or per-collector) may contain `${SECRET_NAME}`,
substituted from an injected secret — for providers that put an API key in the URL, e.g.
`"https://base-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}"`.

### Schema field types supported

`uint*`, `address`, `bool`, `bytes32`, `bytes`, `string`.

## Networks & gas-free testing

`chain.network` is a preset that fills `eas`, `schema_registry`, `chain_id` and default public
`rpcs` for any of those you don't set explicitly (all EAS addresses verified against the official
`eas-contracts` deployments):

| network | chain_id | EAS |
|---------|----------|-----|
| `base` | 8453 | `0x4200…0021` |
| `base-sepolia` | 84532 | `0x4200…0021` |
| `optimism` | 10 | `0x4200…0021` |
| `arbitrum` | 42161 | `0xbD75f629…c458` |
| `ethereum` | 1 | `0xA1207F3B…Ce587` |
| `sepolia` | 11155111 | `0xC2679fBD…815e` |

Two ways to test without spending real value:

- **`mode: "dry_run"`** — collect + build calldata, broadcast nothing, no key needed. Zero cost.
- **`network: "base-sepolia"`** (or `sepolia`) — a full real `attest`/`register_schema` against a
  testnet EAS, paid with **faucet gas**. Attestations show up on `base-sepolia.easscan.org`. This is
  the way to rehearse the end-to-end flow (including broadcast) before going to Base mainnet.

## Output (attest)

```jsonc
{
  "success": true,
  "mode": "attest",
  "block_number": 21345678,
  "schema_uid": "0x…",
  "attestation_data": "0x…",     // the ABI-encoded schema payload
  "calldata": "0x…",             // the exact attest() calldata submitted
  "collected": [                 // per-field evidence, incl. which RPCs agreed
    { "field": "locked", "type": "uint256", "source": "erc20_balance",
      "value_hex": "0x…", "agreed_by": ["https://rpc1", "https://rpc2"] }
  ],
  "attester": "0x…",
  "tx_hash": "0x…",
  "attester_url": "https://base.easscan.org/address/0x…"
}
```

Use `mode: "dry_run"` to get `attestation_data` + `calldata` and the would-be attester **without
broadcasting** — the way to preview an attestation before spending gas.

## Registering a schema (one-time)

```jsonc
{ "mode": "register_schema",
  "chain": { "rpcs": [...], "schema_registry": "0x<SchemaRegistry>" },
  "key_env": "PROTECTED_EAS_KEY",
  "schema": { "definition": "uint256 locked,uint256 minted,uint64 blockNumber",
              "resolver": "0x0", "revocable": true } }
```

Returns the `predicted_schema_uid` (EAS derives it as
`keccak256(abi.encodePacked(schema, resolver, revocable))`) — use that as `schema.uid` when
attesting.

## Secrets

The attester key is an encrypted OutLayer secret, decrypted only inside the TEE and injected as an
env var by the name in `key_env`. Prefer the `PROTECTED_` convention (generated in-enclave, never
exportable) for keys OutLayer manages; a user-supplied key is stored encrypted client-side. See
the [CLI docs](https://github.com/out-layer/cli) (`outlayer secrets set`) or the
[dashboard secrets page](https://app.outlayer.ai/secrets). The key must hold enough native coin on the target
chain to pay gas.

## Build & run locally

```bash
./build.sh
cat example-job.json | wasmtime -S http target/wasm32-wasip2/release/eas-attestor.wasm
```

Targets `wasm32-wasip2` (component model — required for outbound HTTP). Pure-Rust EVM primitives
(`k256` ECDSA, `tiny-keccak`, `rlp`), no native deps.

## Verification & honesty

Every attestation is a public on-chain event: anyone can look up the attester address on the chain's
EAS explorer (e.g. `base.easscan.org`) and cross-check the DCAP attestation of the OutLayer worker
that signed it. Publish claims of the form *"OutLayer publishes TEE-attested &lt;X&gt; on &lt;chain&gt; via
EAS"* only for data actually attested on **mainnet**, and link both the easscan page and
workers.outlayer.ai so the claim is independently verifiable.

## Web form

[`web/`](web/) is a self-contained page that builds a job, runs it through the OutLayer HTTPS API and
shows the evidence, the explorer links and the enclave quote. No build step and no external requests
— open the file, or serve the folder as a static site.

## License

MIT or Apache-2.0, at your option — see [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
