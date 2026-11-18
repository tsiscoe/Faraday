# Installing Faraday

Installing Faraday takes about two minutes. Recovering from a leaked production key takes about two years, a lawyer, and a very quiet all-hands meeting. Choose wisely.

## Prerequisites

- **Rust `1.85+`** (2024 Edition) via [rustup.rs](https://rustup.rs/). If you're still on an older toolchain, Faraday can't help you, and frankly neither can therapy.
- **A supported platform:**
  - Windows 10 / 11 (`x86_64-pc-windows-msvc`)
  - Linux (`x86_64-unknown-linux-gnu`)
  - macOS 13+ (`aarch64-apple-darwin` & `x86_64-apple-darwin`)

The first build compiles a bundled SQLite. It takes a while. Make a coffee. Contemplate how many plaintext `.env` files you've committed over the years. Make it a strong coffee.

## Build from Source

```bash
git clone https://github.com/tsiscoe/Faraday.git
cd Faraday
cargo build --release
```

The binary lands at `target/release/faraday` (or `faraday.exe` on Windows). To put it on your `PATH`:

```bash
cargo install --path .
```

## Environment Variables

Yes, a tool that exists to get secrets out of environment variables reads two of its own from the environment. The irony isn't lost on us. Both are stripped from every child process Faraday spawns, so they never reach the program you're running.

| Variable | What It Does | Default |
| :--- | :--- | :--- |
| `FARADAY_PASSPHRASE` | Master passphrase for non-interactive use (CI pipelines). | Interactive prompt, or the OS keyring with `--keyring` |
| `FARADAY_DB_PATH` | Location of the encrypted SQLite WAL vault. | `%LOCALAPPDATA%\faraday\faraday.db` (Windows) or `~/.local/share/faraday/faraday.db` (Unix) |

For day-to-day work, use `--keyring`. It stores the passphrase in Windows Credential Manager, macOS Keychain, or the Linux kernel keyring, which is a great deal safer than your shell history, a sticky note, or the Slack DM you sent yourself in 2022.

## Verify the Install

```bash
faraday --version
faraday --keyring init
```

If `init` prints a vault path and zero stored secrets, congratulations: you now own a vault with nothing in it. Go feed it your `.env` file with `faraday import --shred` and watch the plaintext disappear.
