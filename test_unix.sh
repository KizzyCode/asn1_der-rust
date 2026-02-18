#!/bin/bash
set -e

cargo test --verbose --release --no-default-features

cargo test --verbose --release --no-default-features --features="std"
cargo test --verbose --release --no-default-features --features="native_types"
cargo test --verbose --release --no-default-features --features="std,native_types"

cargo run --verbose --release --no-default-features --features="no_panic" --example="nopanic"
cargo run --verbose --release --no-default-features --features="no_panic,std" --example="nopanic"
cargo run --verbose --release --no-default-features --features="no_panic,native_types" --example="nopanic"
cargo run --verbose --release --no-default-features --features="no_panic,std,native_types" --example="nopanic"
