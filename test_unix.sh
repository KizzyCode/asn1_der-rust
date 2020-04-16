#!/bin/bash
set -e

cargo clean && cargo test --verbose --release --no-default-features

cargo test --verbose --release --no-default-features --features="native_types"
cargo test --verbose --release --no-default-features --features="no_std"
cargo clean && cargo test --verbose --release --no-default-features --features="no_panic"

cargo test --verbose --release --no-default-features --features="native_types,no_std"
cargo clean && cargo test --verbose --release --no-default-features --features="no_std,no_panic"
cargo clean && cargo test --verbose --release --no-default-features --features="no_panic,native_types"

cargo clean && cargo test --verbose --release --no-default-features --features="native_types,no_std,no_panic"
