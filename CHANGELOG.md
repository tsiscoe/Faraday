# Changelog

All notable changes to **Faraday** (`faraday-cage`) are documented in this file.

## [0.1.0] - 2026-11-17

### Added
- **Two-Tier `XChaCha20-Poly1305` Cryptographic Core (`src/crypto/mod.rs`):** `Argon2id` (`m=64 MiB, t=3, p=4`) + `HKDF-SHA256` subkey expansion (`kek_key`, `mac_key`, `verifier`), per-secret 256-bit `DEK` envelope encryption with contextual AAD (`faraday-v1|<scope>|<key>|dek` and `|val`), `constant_time_eq_32` (`CWE-208`), and `ZeroizeOnDrop` (`CWE-316`).
- **Atomic SQLite WAL Vault & Fail-Closed ACLs (`src/vault/mod.rs`):** Bundled `rusqlite 0.42.0` (`SQLite 3.51.2+`) WAL store with `PRAGMA secure_delete = ON`, `busy_timeout(5000ms)`, `TransactionBehavior::Immediate` (`BEGIN IMMEDIATE`) transactions, and verified owner-only ACL enforcement (`icacls /inheritance:r` on Windows, `0700`/`0600` on Unix) across the vault directory, `.db`, `.db-wal`, and `.db-shm` sidecars.
- **Cancel-Safe Process Secret Injector & 4-Encoding Redaction Cage (`src/cage/mod.rs`):** `FaradayRedactor` (`Aho-Corasick` `LeftmostLongest`) scrubbing Raw, Base64 (`STANDARD` & `URL_SAFE_NO_PAD`), URL-encoded, and Hex-encoded secret leaks from child `stdout`/`stderr` streams into `[FARADAY:REDACTED:<KEY>:<TAG>]`, paired with `CancelSafeLineReader` (`4 MiB` bound) and child environment scrubbing (`FARADAY_*`/`LOOM_*`/`SIGNET_*` + optional `--isolate-env`).
- **`.env` Harvester & Zero-Fill Shredder (`src/dotenv/mod.rs`):** Parses `.env` files (`16 MiB` bound), imports pairs atomically, and overwrites plaintext `.env` files with `0x00` bytes (`sync_all`) before deletion when `--shred` is specified.
- **Clap v4 CLI & Ratatui v0.30+ 3-Pane Cage Monitor (`src/cli.rs`, `src/tui/`):** Added `faraday init`, `faraday set`, `faraday get`, `faraday list`, `faraday rm`, `faraday import`, `faraday run`, `faraday audit`, and `faraday tui` with `sanitize_terminal_str` (`CWE-150`).
