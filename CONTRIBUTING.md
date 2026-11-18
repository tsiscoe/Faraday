# Contributing to Faraday

So you want to contribute to a security tool. Brave. Most people's idea of contributing to security is changing their password from `Summer2025!` to `Summer2026!` and calling it a rotation policy.

Every pull request has to clear these gates. They're not suggestions. CI enforces them, and CI has no feelings to appeal to.

## The Gates

1. **Zero `unsafe` code.** `#![forbid(unsafe_code)]` is set crate-wide. If your patch needs `unsafe`, it doesn't need to be in this crate.
2. **Formatting.** `cargo fmt --all -- --check` must produce zero diff. We're not having a debate about brace placement in a tool whose whole job is to be boring and correct.
3. **Lints.** `cargo clippy --all-targets -- -D warnings` must pass on Windows, Linux, and macOS. CI runs the lint job first, and the test jobs won't even start until it's green, so you'll find out you forgot something before you find out what else you broke.
4. **Tests.** `cargo test` must pass 100%, including the 128-case `proptest!` suites and the live child-process redaction test. A test suite that "mostly passes" is a test suite that's lying to you politely.
5. **Sterile fixtures.** Build test secrets at runtime with `format!` instead of pasting literal tokens, IPs, emails, or home directory paths into the source. Static scanners such as `loom audit --fail-on-leak` must report **0 findings**. A secret-protection tool that ships secrets in its own test folder is just performance art.

## Running the Gates Locally

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run them in that order. Lints first, tests second. Finding a style error after a seven-minute test run is the kind of thing that makes people take up drinking at lunch.

## Reporting a Vulnerability

Don't open a public issue titled "lol your redactor misses rot13." Contact the maintainer privately through GitHub with a reproduction. We'd rather hear about it from you than read about it in someone's conference talk.
