# Changelog

Every notable change to **Faraday** (`faraday-cage`) goes here. Unlike your production logs, this file is supposed to contain the history of what happened.

## [0.1.0] - 2026-11-17

The first release. The `.env` file has been served its eviction notice.

### Added
- **Two-tier `XChaCha20-Poly1305` crypto core (`src/crypto/mod.rs`).** `Argon2id` (`m=64 MiB, t=3, p=4`) plus `HKDF-SHA256` derive `kek_key`, `mac_key`, and `verifier`. Every secret gets its own 256-bit DEK, with AAD binding the ciphertext to its scope and key name (`faraday-v1|<scope>|<key>|dek` and `|val`). Constant-time verifier comparison (`CWE-208`) and zeroize-on-drop for key material (`CWE-316`).
- **Atomic SQLite WAL vault (`src/vault/mod.rs`).** Bundled `rusqlite 0.42.0` with `PRAGMA secure_delete = ON`, a 5-second busy timeout, and `BEGIN IMMEDIATE` on every write (`CWE-362`). Owner-only permissions on the vault directory, `.db`, `.db-wal`, and `.db-shm`, and Faraday fails closed if it can't apply them (`CWE-732`).
- **Process injector and 4-encoding redaction cage (`src/cage/mod.rs`).** `FaradayRedactor` scrubs raw, Base64 (standard and URL-safe), RFC 3986 URL-encoded, and hex-encoded secret leaks from child `stdout`/`stderr` into `[FARADAY:REDACTED:<KEY>:<TAG>]`. Built on a cancel-safe line reader (4 MiB cap), control-variable stripping (`CWE-526`), optional `--isolate-env`, 10-second write timeouts, and guaranteed child reaping.
- **`.env` importer and zero-fill shredder (`src/dotenv/mod.rs`).** Parses `.env` files up to 16 MiB (quotes, `export`, inline comments, escapes), imports in one atomic transaction, and with `--shred` overwrites the file with `0x00`, syncs it to disk, and deletes it.
- **CLI and terminal dashboard (`src/cli.rs`, `src/tui/`).** `init`, `set`, `get` (masked unless you pass `--reveal`), `list`, `rm`, `import`, `run`, `audit`, and `tui`, a 3-pane Ratatui v0.30 monitor that strips ANSI/OSC escape sequences before rendering anything (`CWE-150`).
- **CI.** A lint job (`rustfmt` + `clippy -D warnings`) runs on Windows, Linux, and macOS before any test job is allowed to start, followed by cross-platform tests and a RustSec dependency audit.
