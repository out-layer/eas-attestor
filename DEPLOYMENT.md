# Deploying eas-attestor

Rehearse everything on **testnet + Base Sepolia** first: both the OutLayer side and the EAS side are
free there (faucet gas), and the flow is identical to mainnet.

| | testnet | mainnet |
|---|---|---|
| OutLayer contract | `outlayer.testnet` | `outlayer.near` |
| OutLayer API | `https://testnet-api.outlayer.ai` | `https://api.outlayer.ai` |
| NEAR RPC | `https://rpc.testnet.fastnear.com` | `https://rpc.mainnet.fastnear.com` |
| EAS chain to target | `base-sepolia` | `base` |

## 1. Build

```bash
./build.sh          # -> target/wasm32-wasip2/release/eas-attestor.wasm
```

## 2. Register the project on-chain

A project is created by one on-chain call — there is no HTTPS deploy endpoint, and the owner is
always the caller. The code source is either a GitHub repo+commit or a URL+hash; **there is no
subdirectory support for the GitHub variant** (the compiler builds from the repo root), so while
this app lives inside the monorepo, deploy it by URL.

### Quick path — upload the wasm and register it by hash

```bash
outlayer upload target/wasm32-wasip2/release/eas-attestor.wasm   # returns the FastFS URL
shasum -a 256 target/wasm32-wasip2/release/eas-attestor.wasm     # the hash below
```

```bash
near call outlayer.testnet create_project '{
  "name": "eas-attestor",
  "source": { "WasmUrl": {
    "url": "https://<sender>.fastfs.io/<receiver>/<hash>.wasm",
    "hash": "<sha256 hex>",
    "build_target": "wasm32-wasip2"
  }}
}' --accountId you.testnet --deposit 0.1
```

The project id becomes `you.testnet/eas-attestor` — that is what the HTTPS API and the web form take.

### Proper path — its own repository

Every other WASI app here is a standalone `out-layer/*` repo added back as a submodule. Once
`eas-attestor` is extracted the same way, register it from source so the enclave compiles the code
anyone can read:

```bash
near call outlayer.near create_project '{
  "name": "eas-attestor",
  "source": { "GitHub": {
    "repo": "out-layer/eas-attestor",
    "commit": "<full 40-char sha>",
    "build_target": "wasm32-wasip2"
  }}
}' --accountId you.near --deposit 0.1
```

Later versions: `add_version` + `set_active_version`.

## 3. Create the attester key as a secret

The signing key is an OutLayer secret named by `key_env`. Either way, create it from the dashboard
secrets page — it holds the wallet and the enclave's public key — and bind it to the project
(`accessor: {"Project": {"project_id": "you.near/eas-attestor"}}`) so it survives a rename.
`vault_id` must be present in the contract call even when it is `null`.

**Generated in the enclave** (`PROTECTED_EAS_KEY`, spec `hex32`). The spec produces 32 random bytes
inside the TEE, which is exactly a secp256k1 private key — what this job expects. No private key
ever exists outside the enclave: nothing to export, paste, leak, or rotate out of a browser. The
enclave never reveals the private half and nothing returns the derived address, but this job derives
it — run a **dry run** and read `attester`, then send that address a dollar of native gas.

**Your own key.** Supported, and the fastest way to make a first attestation if you already have a
funded account: put the key in the secret form and point `key_env` at it. Understand the trade you
are making — the key passes through the browser, and an account reused from elsewhere ties every
attestation to its entire on-chain history. Use a key dedicated to attesting rather than one holding
real balances, and never put a private key in a URL.

Note that the convenience of "an account that already has gas" comes precisely from reusing a funded
personal account. A fresh dedicated key has to be funded too — the same single transfer the generated
path needs — so once you are past the first test, the generated key costs nothing extra and removes
the export step entirely.

## 4. Register the EAS schema (once per schema)

```bash
curl -X POST https://testnet-api.outlayer.ai/call/you.testnet/eas-attestor \
  -H 'Content-Type: application/json' \
  -H 'X-Payment-Key: owner:nonce:key' \
  -d '{
    "input": {
      "mode": "register_schema",
      "chain": { "network": "base-sepolia" },
      "key_env": "PROTECTED_EAS_KEY",
      "schema": { "definition": "uint256 lockedOnEthereum,uint256 mintedSupply,string teeAttestation,uint64 blockNumber",
                  "resolver": "0x0", "revocable": true }
    },
    "secrets_ref": { "profile": "eas", "account_id": "you.testnet" },
    "async": true
  }'
```

The response carries `call_id` and `attestation_url`; poll `GET /calls/{call_id}` with the same
payment key. The job returns `predicted_schema_uid` — that is the `schema.uid` for every attestation
afterwards.

## 5. Attest

Same request with `"mode": "attest"`, the `schema.uid` from step 4, and a `collect` array with one
entry per schema field. See [README.md](README.md) for the collectors and
[example-crosschain-por.json](example-crosschain-por.json) for a cross-chain proof-of-reserves job.

Include a `tee_attestation` source so the attestation carries a link to the Intel TDX quote of the
very run that produced it — that is what makes the "TEE-attested" claim checkable by a stranger
rather than something they have to take on trust.

## Notes that will bite otherwise

- **Always call with `"async": true` and poll.** A synchronous call can outlive the ~100 s edge
  timeout in front of the API and be cut off mid-execution.
- **A failed execution still returns HTTP 200** with `status: "failed"` and an `error` — check the
  body, not the status code. An unknown `call_id` answers 500, not 404.
- **Payment keys are bearer credentials** against a USDC balance, formatted `owner:nonce:key` with a
  64-hex key. Scope one to this project (`metadata.project_ids`, `max_per_call`) before using it
  anywhere near a browser.
- **Do not use a `wk_` trial key in a browser.** The same token also authorizes the custody wallet
  API — signing, transfers, account deletion — not just execution.
- The HTTPS API is rate limited to **100 requests/minute per IP**, shared by everyone behind the same
  address, and returns 429 as **plain text**, not JSON.
