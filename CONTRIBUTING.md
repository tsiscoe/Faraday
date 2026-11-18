# Contributing to Faraday

Thank you for contributing to **Faraday** (`faraday-cage`)! All changes must satisfy the following security and engineering gates before merge:

1. **Zero Unsafe Code:** `#![forbid(unsafe_code)]` is enforced across the entire crate.
2. **Formatting:** `cargo fmt --all -- --check` must pass with `0` diff lines.
3. **Static Analysis:** `cargo clippy --all-targets -- -D warnings` must pass with `0` warnings.
4. **Cryptographic & Property Tests:** `cargo test` (including `proptest!` Two-Tier AEAD & 4-encoding stream redaction suites) must pass 100%.
5. **Sterile Fixtures:** Construct test secret fixtures dynamically at runtime so static repository scanners (`loom audit --fail-on-leak`) report `0` findings.
