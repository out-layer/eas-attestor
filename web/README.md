# Web form

A single self-contained page for configuring and running an attestation: pick a chain, describe the
EAS schema, point each field at a data source (on this chain or another one), and run it through the
OutLayer HTTPS API. It shows the collected evidence, the schema-encoded payload, the explorer links
and the Intel TDX quote for that exact run — and always the job JSON plus an equivalent `curl`
command, so nothing here is a black box.

No build step, no bundler, no external requests: one `index.html` with its CSS and JS inline. The
only hosts it ever talks to are the OutLayer API and the block explorers you follow by hand.

## Running it

```bash
open index.html                 # straight from disk
python3 -m http.server 8000     # or serve the folder
```

Either works — the API allows browser calls from any origin.

## Deploying it

Copy the folder to any static host; it has no server-side component. Intended to live on an OutLayer
subdomain.

## What it needs

- **A deployed project.** The page calls `POST /call/{owner}/{project}`, so `eas-attestor` must be
  registered on-chain first — see [../DEPLOYMENT.md](../DEPLOYMENT.md).
- **A payment key**, entered by the visitor, in `owner:nonce:key` form. It is used only by the
  visitor's own browser to authorize their run; the page stores nothing and sends it nowhere else.
  Scope the key to this project before using it.
- **A secret holding the attester key**, referenced by profile and owner account. Secrets are created
  on [app.outlayer.ai/secrets](https://app.outlayer.ai/secrets) — the page links there carrying only
  the shape of the secret (project, profile, name), never a value.

Sponsored runs — where OutLayer pays for the execution and the visitor only pays chain gas — need a
small server-side proxy holding that payment key. A static page cannot do it: a payment key shipped
in JavaScript is a spendable credential handed to every visitor.
