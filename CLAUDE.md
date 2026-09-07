# min_shark — Claude notes

## Formatting

CI uses **nightly** rustfmt (`dtolnay/rust-toolchain@nightly`, no pin). Always format with:

```
cargo +nightly fmt --all
```

Stable `cargo fmt` silently ignores `imports_layout` and `imports_granularity` from `rustfmt.toml`, producing output that fails the CI `Rustfmt` check.

## Pre-push check

Run `./precheck.sh` before pushing to mirror all three required CI checks (fmt, clippy, tests) locally.
