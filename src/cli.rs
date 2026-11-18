//! Clap v4 CLI surface for **Faraday** (`init`, `set`, `get`, `list`, `rm`, `import`, `run`, `audit`, `tui`).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "faraday",
    version,
    about = "Faraday: Zero-Disk Process Secret Injector & Live 4-Encoding Stdout/Stderr Leak Redaction Cage"
)]
pub struct Cli {
    /// Path to the Faraday SQLite WAL vault (defaults to %LOCALAPPDATA%/faraday/faraday.db).
    #[arg(long, env = "FARADAY_DB_PATH", global = true)]
    pub db: Option<PathBuf>,

    /// Master passphrase used to unlock the Two-Tier XChaCha20-Poly1305 secret vault.
    #[arg(long, env = "FARADAY_PASSPHRASE", global = true)]
    pub passphrase: Option<String>,

    /// Store or load the master passphrase from the OS native keyring (`windows-native`, `apple-native`, `linux-native`).
    #[arg(long, global = true, default_value_t = false)]
    pub keyring: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize the Faraday SQLite WAL vault and lock owner-only filesystem ACLs.
    Init,

    /// Encrypt and store a secret in a named environment scope (`dev`, `staging`, `prod`).
    Set {
        /// Environment scope (e.g., `dev`, `staging`, `prod`).
        #[arg(long, default_value = "dev")]
        scope: String,

        /// Environment variable name (e.g., `OPENAI_API_KEY`, `DATABASE_URL`).
        #[arg(long)]
        key: String,

        /// Secret value (if omitted, prompts interactively without terminal echo).
        #[arg(long)]
        value: Option<String>,
    },

    /// Decrypt and print a single secret value (requires explicit `--reveal` flag to prevent accidental LLM context leaks).
    Get {
        /// Environment scope.
        #[arg(long, default_value = "dev")]
        scope: String,

        /// Environment variable name.
        #[arg(long)]
        key: String,

        /// Explicitly reveal the plaintext secret on stdout (otherwise prints only the BLAKE3 fingerprint tag).
        #[arg(long, default_value_t = false)]
        reveal: bool,
    },

    /// List stored secret metadata (scope, key name, BLAKE3 fingerprint tag, and timestamp — never plaintext values).
    List {
        /// Optional scope filter.
        #[arg(long)]
        scope: Option<String>,

        /// Emit as JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Delete a secret from a scope.
    Rm {
        /// Environment scope.
        #[arg(long, default_value = "dev")]
        scope: String,

        /// Environment variable name.
        #[arg(long)]
        key: String,
    },

    /// Import key-value pairs from a `.env` file into the encrypted vault, optionally zero-fill shredding the `.env` file.
    Import {
        /// Target environment scope (e.g., `dev`, `prod`).
        #[arg(long, default_value = "dev")]
        scope: String,

        /// Path to the `.env` file to import.
        #[arg(long, default_value = ".env")]
        file: PathBuf,

        /// Overwrite the plaintext `.env` file on disk with `0x00` bytes (`sync_all`) and delete it after import.
        #[arg(long, default_value_t = false)]
        shred: bool,
    },

    /// Spawn a child command with scoped secrets injected into memory and live 4-encoding stdout/stderr leak redaction.
    Run {
        /// Environment scope to inject (`dev`, `staging`, `prod`).
        #[arg(long, default_value = "dev")]
        scope: String,

        /// Clear inherited parent environment variables (`env_clear`) and pass only safe OS baseline variables + scoped secrets.
        #[arg(long, default_value_t = false)]
        isolate_env: bool,

        /// Child command and arguments (after `--`).
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// Display all intercepted stdout/stderr secret leak redaction events recorded by the Faraday Cage.
    Audit {
        /// Emit as JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Launch the Ratatui v0.30+ 3-pane Faraday Cage Monitor.
    Tui,
}
