#!/usr/bin/env bash
set -o nounset
set -o errexit
set -o pipefail

RUST_FMT_VERSION="${RUST_FMT_VERSION:-nightly}"

echo "==> fmt"
cargo "+${RUST_FMT_VERSION}" fmt --check

echo "==> clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> tests"
cargo test --all-targets --all-features

echo "==> all checks passed"
