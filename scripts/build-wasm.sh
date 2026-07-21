#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
rustup target add wasm32-unknown-unknown
cargo build --manifest-path "$root/wasm-engine/Cargo.toml" --target wasm32-unknown-unknown --release
cp "$root/wasm-engine/target/wasm32-unknown-unknown/release/tcpform_wasm_engine.wasm" "$root/dashboard/tcpform-engine.wasm"
