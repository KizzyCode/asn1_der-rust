#!/bin/bash
set -e

cargo clean && cargo test --verbose --release --no-default-features

cargo test --verbose --release --no-default-features --features="native_types"
cargo test --verbose --release --no-default-features --features="std"
#cargo clean && cargo test --verbose --release --no-default-features --features="no_panic"

cargo test --verbose --release --no-default-features --features="native_types,std"
#cargo clean && cargo test --verbose --release --no-default-features --features="std,no_panic"
#cargo clean && cargo test --verbose --release --no-default-features --features="no_panic,native_types"

#cargo clean && cargo test --verbose --release --no-default-features --features="native_types,std,no_panic"
