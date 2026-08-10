#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "Building eas-attestor for wasm32-wasip2..."
rustup target add wasm32-wasip2 2>/dev/null || true
cargo build --target wasm32-wasip2 --release

echo ""
echo "Build complete:"
ls -lh target/wasm32-wasip2/release/eas-attestor.wasm
echo ""
echo "Dry run (needs outbound HTTP, hence -S http):"
echo "  cat example-job.json | wasmtime -S http target/wasm32-wasip2/release/eas-attestor.wasm"
