![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/dovreshef/min_shark/.github%2Fworkflows%2Frust.yml)
![docs.rs](https://img.shields.io/docsrs/min_shark)
![Crates.io](https://img.shields.io/crates/l/min_shark)
![Codecov](https://img.shields.io/codecov/c/github/dovreshef/min_shark)
![Crates.io](https://img.shields.io/crates/v/min_shark)

This is a parser and execution engine for minimal Wireshark®-like filters.

See [here](docs/syntax.md) for supported syntax.

Usage example:

```rust

    let filter = "ip.addr in {192.168.1.0/24, 10.1.1.0/24} and payload ~ '(?i)CaSeInSeNsItIvE'";
    let expression = min_shark::parse(filter);

    // .. later
    let is_match = expression
        .matcher()
        .tcp(true)
        .src_ip("1.1.1.1/24".parse().unwrap())
        .payload(b"CaseInsensitive")
        .is_match();

    assert_eq!(is_match, true);

```
