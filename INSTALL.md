# Installing Faraday (`faraday-cage`)

## Prerequisites

- **Rust Toolchain:** Rust `1.85+` (2024 Edition) via [rustup.rs](https://rustup.rs/)
- **Supported Platforms:**
  - Windows 10 / 11 (`x86_64-pc-windows-msvc`)
  - Linux (`x86_64-unknown-linux-gnu`)
  - macOS 13+ (`aarch64-apple-darwin` & `x86_64-apple-darwin`)

---

## Build from Source

```bash
git clone https://github.com/tsiscoe/Faraday.git
cd Faraday
cargo build --release
```

---

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `FARADAY_PASSPHRASE` | Master passphrase for non-interactive CLI / CI pipelines | Interactive prompt or OS Keyring (`--keyring`) |
| `FARADAY_DB_PATH` | Path to the SQLite WAL secret vault | `%LOCALAPPDATA%\faraday\faraday.db` (Win) or `~/.local/share/faraday/faraday.db` (Unix) |
