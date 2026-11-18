//! Two-Tier `XChaCha20-Poly1305` SQLite WAL Secret Vault & Redaction Audit Store (`faraday.db`).
//!
//! Pre-Hardened Invariants:
//! - **Two-Tier Per-Secret DEKs + Contextual AAD:** Every secret row stores `wrapped_dek` and
//!   `ciphertext` bound to `faraday-v1|<scope>|<key_name>|dek` and `|val`. Swapping ciphertexts
//!   across scopes or variable names fails authentication immediately.
//! - **Atomic `BEGIN IMMEDIATE` Transactions (`CWE-362`):** All mutations (`set_secret`,
//!   `import_secrets_atomic`, `delete_secret`, `record_redaction_event`) execute inside
//!   `TransactionBehavior::Immediate` with `PRAGMA secure_delete = ON` and `busy_timeout(5000ms)`.
//! - **Verified Fail-Closed Vault & Sidecar ACLs (`CWE-732`):** `enforce_vault_and_sidecar_acls`
//!   verifies `icacls /inheritance:r` exit status `0` on Windows (`0700`/`0600` on Unix) across
//!   the parent directory, `faraday.db`, `faraday.db-wal`, and `faraday.db-shm` after WAL init.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{
    MasterSeed, SALT_LEN, VaultSubkeys, compute_secret_short_tag, constant_time_eq_32,
    generate_salt, open_two_tier_secret, seal_two_tier_secret,
};

/// Public metadata for a stored secret (value is never included in metadata).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMetadata {
    pub scope: String,
    pub key_name: String,
    pub blake3_tag: String,
    pub updated_at: String,
}

/// Decrypted secret entry used transiently inside `faraday run` before immediate zeroization.
#[derive(Clone)]
pub struct DecryptedScopedSecret {
    pub scope: String,
    pub key_name: String,
    pub value: String,
    pub blake3_tag: String,
}

impl Drop for DecryptedScopedSecret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Recorded redaction event when Faraday intercepts a secret leak in child `stdout` or `stderr`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionAuditEvent {
    pub id: i64,
    pub timestamp: String,
    pub scope: String,
    pub command: String,
    pub stream: String,
    pub key_name: String,
    pub encoding_matched: String,
    pub blake3_tag: String,
}

/// SQLite WAL store managing Two-Tier AEAD scoped secrets and stream redaction audit logs.
pub struct FaradayVault {
    conn: Connection,
    db_path: PathBuf,
    subkeys: VaultSubkeys,
}

impl FaradayVault {
    /// Open or initialize a `FaradayVault` at `db_path` using `passphrase`.
    pub fn open_with_passphrase(db_path: &Path, passphrase: &[u8], fast_kdf: bool) -> Result<Self> {
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create Faraday vault directory {}",
                    parent.display()
                )
            })?;
            if !fast_kdf {
                enforce_owner_only_acl(parent, true)?;
            }
        }

        let conn = Connection::open(db_path).with_context(|| {
            format!(
                "failed to open Faraday SQLite vault at {}",
                db_path.display()
            )
        })?;

        conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;

        Self::init_schema(&conn)?;

        let existing_meta = Self::load_meta(&conn)?;
        let subkeys = match existing_meta {
            Some((salt, expected_verifier)) => {
                let seed = if fast_kdf {
                    MasterSeed::derive_fast_for_test(passphrase, &salt)?
                } else {
                    MasterSeed::derive_from_passphrase(passphrase, &salt)?
                };
                let sk = seed.derive_subkeys(&salt)?;
                if !constant_time_eq_32(&sk.verifier, &expected_verifier) {
                    return Err(anyhow!(
                        "Invalid master passphrase for Faraday vault at {}",
                        db_path.display()
                    ));
                }
                sk
            }
            None => {
                let salt = generate_salt();
                let seed = if fast_kdf {
                    MasterSeed::derive_fast_for_test(passphrase, &salt)?
                } else {
                    MasterSeed::derive_from_passphrase(passphrase, &salt)?
                };
                let sk = seed.derive_subkeys(&salt)?;
                Self::save_meta(&conn, &salt, &sk.verifier)?;
                sk
            }
        };

        if !fast_kdf {
            enforce_vault_and_sidecar_acls(db_path)?;
        }

        Ok(Self {
            conn,
            db_path: db_path.to_path_buf(),
            subkeys,
        })
    }

    /// Open an in-memory `FaradayVault` for fast unit and `proptest!` suites.
    pub fn open_in_memory_for_test(passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        let salt = [0x5Au8; SALT_LEN];
        let seed = MasterSeed::derive_fast_for_test(passphrase, &salt)?;
        let subkeys = seed.derive_subkeys(&salt)?;
        Self::save_meta(&conn, &salt, &subkeys.verifier)?;
        Ok(Self {
            conn,
            db_path: PathBuf::from(":memory:"),
            subkeys,
        })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS faraday_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scoped_secrets (
                scope TEXT NOT NULL,
                key_name TEXT NOT NULL,
                wrapped_dek BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                blake3_tag TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (scope, key_name)
            );

            CREATE TABLE IF NOT EXISTS redaction_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                scope TEXT NOT NULL,
                command TEXT NOT NULL,
                stream TEXT NOT NULL,
                key_name TEXT NOT NULL,
                encoding_matched TEXT NOT NULL,
                blake3_tag TEXT NOT NULL
            );",
        )
        .context("failed to initialize Faraday SQLite schema")?;
        Ok(())
    }

    fn load_meta(conn: &Connection) -> Result<Option<([u8; SALT_LEN], [u8; 32])>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT salt, verifier FROM faraday_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((s, v)) = row {
            let salt: [u8; SALT_LEN] = s.try_into().map_err(|_| anyhow!("bad salt length"))?;
            let verifier: [u8; 32] = v.try_into().map_err(|_| anyhow!("bad verifier length"))?;
            Ok(Some((salt, verifier)))
        } else {
            Ok(None)
        }
    }

    fn save_meta(conn: &Connection, salt: &[u8; SALT_LEN], verifier: &[u8; 32]) -> Result<()> {
        conn.execute(
            "INSERT INTO faraday_meta (id, salt, verifier, created_at) VALUES (1, ?1, ?2, ?3)",
            params![
                salt.as_slice(),
                verifier.as_slice(),
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn subkeys(&self) -> &VaultSubkeys {
        &self.subkeys
    }

    /// Validate that `scope` and `key_name` are clean, non-empty identifiers.
    pub fn validate_scope_and_key(scope: &str, key_name: &str) -> Result<()> {
        let s = scope.trim();
        let k = key_name.trim();
        if s.is_empty()
            || s.len() > 64
            || !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(anyhow!(
                "Invalid scope '{scope}': must be 1..64 ASCII alphanumeric, '_', or '-' characters"
            ));
        }
        if k.is_empty()
            || k.len() > 128
            || k.as_bytes()[0].is_ascii_digit()
            || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(anyhow!(
                "Invalid environment variable key '{key_name}': must be a valid POSIX/Win32 env identifier"
            ));
        }
        Ok(())
    }

    /// Encrypt and store a single `(scope, key_name, value)` secret inside a `BEGIN IMMEDIATE` transaction.
    pub fn set_secret(&self, scope: &str, key_name: &str, value: &str) -> Result<SecretMetadata> {
        Self::validate_scope_and_key(scope, key_name)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .context("failed to start BEGIN IMMEDIATE transaction for set_secret")?;
        let meta = self.set_secret_in_tx(&tx, scope, key_name, value)?;
        tx.commit()?;
        Ok(meta)
    }

    fn set_secret_in_tx(
        &self,
        tx: &Transaction<'_>,
        scope: &str,
        key_name: &str,
        value: &str,
    ) -> Result<SecretMetadata> {
        let env = seal_two_tier_secret(&self.subkeys.kek_key, scope, key_name, value.as_bytes())?;
        let tag = compute_secret_short_tag(&self.subkeys.mac_key, scope, key_name, value);
        let now = Utc::now().to_rfc3339();

        tx.execute(
            "INSERT INTO scoped_secrets (scope, key_name, wrapped_dek, ciphertext, blake3_tag, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(scope, key_name) DO UPDATE SET
                 wrapped_dek = excluded.wrapped_dek,
                 ciphertext = excluded.ciphertext,
                 blake3_tag = excluded.blake3_tag,
                 updated_at = excluded.updated_at",
            params![scope, key_name, &env.wrapped_dek, &env.ciphertext, &tag, &now],
        )?;

        Ok(SecretMetadata {
            scope: scope.to_string(),
            key_name: key_name.to_string(),
            blake3_tag: tag,
            updated_at: now,
        })
    }

    /// Atomically import a batch of `(key_name, value)` pairs into `scope` inside a single
    /// `BEGIN IMMEDIATE` transaction. If any key is invalid, zero secrets are committed.
    pub fn import_secrets_atomic(
        &self,
        scope: &str,
        pairs: &[(String, String)],
    ) -> Result<Vec<SecretMetadata>> {
        for (k, _) in pairs {
            Self::validate_scope_and_key(scope, k)?;
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)
            .context("failed to start BEGIN IMMEDIATE transaction for batch import")?;
        let mut out = Vec::with_capacity(pairs.len());
        for (k, v) in pairs {
            out.push(self.set_secret_in_tx(&tx, scope, k, v)?);
        }
        tx.commit()?;
        Ok(out)
    }

    /// Retrieve and decrypt a single secret `(scope, key_name)`.
    pub fn get_secret(&self, scope: &str, key_name: &str) -> Result<Option<DecryptedScopedSecret>> {
        let row: Option<(Vec<u8>, Vec<u8>, String)> = self
            .conn
            .query_row(
                "SELECT wrapped_dek, ciphertext, blake3_tag FROM scoped_secrets WHERE scope = ?1 AND key_name = ?2",
                params![scope, key_name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let Some((wrapped_dek, ciphertext, blake3_tag)) = row else {
            return Ok(None);
        };

        let dec = open_two_tier_secret(
            &self.subkeys.kek_key,
            scope,
            key_name,
            &wrapped_dek,
            &ciphertext,
        )?;
        Ok(Some(DecryptedScopedSecret {
            scope: scope.to_string(),
            key_name: key_name.to_string(),
            value: dec.into_utf8_string()?,
            blake3_tag,
        }))
    }

    /// Decrypt all secrets in `scope` for ephemeral injection into `faraday run`.
    pub fn decrypt_scope_secrets(&self, scope: &str) -> Result<Vec<DecryptedScopedSecret>> {
        let mut stmt = self.conn.prepare(
            "SELECT key_name, wrapped_dek, ciphertext, blake3_tag
             FROM scoped_secrets WHERE scope = ?1 ORDER BY key_name ASC",
        )?;
        let mut rows = stmt.query(params![scope])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            let key_name: String = r.get(0)?;
            let wrapped_dek: Vec<u8> = r.get(1)?;
            let ciphertext: Vec<u8> = r.get(2)?;
            let blake3_tag: String = r.get(3)?;

            let dec = open_two_tier_secret(
                &self.subkeys.kek_key,
                scope,
                &key_name,
                &wrapped_dek,
                &ciphertext,
            )?;
            out.push(DecryptedScopedSecret {
                scope: scope.to_string(),
                key_name,
                value: dec.into_utf8_string()?,
                blake3_tag,
            });
        }
        Ok(out)
    }

    /// List secret metadata (never plaintext values), optionally filtered by `scope`.
    pub fn list_secret_metadata(&self, scope: Option<&str>) -> Result<Vec<SecretMetadata>> {
        let mut out = Vec::new();
        if let Some(sc) = scope {
            let mut stmt = self.conn.prepare(
                "SELECT scope, key_name, blake3_tag, updated_at
                 FROM scoped_secrets WHERE scope = ?1 ORDER BY scope ASC, key_name ASC",
            )?;
            let mut rows = stmt.query(params![sc])?;
            while let Some(r) = rows.next()? {
                out.push(SecretMetadata {
                    scope: r.get(0)?,
                    key_name: r.get(1)?,
                    blake3_tag: r.get(2)?,
                    updated_at: r.get(3)?,
                });
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT scope, key_name, blake3_tag, updated_at
                 FROM scoped_secrets ORDER BY scope ASC, key_name ASC",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                out.push(SecretMetadata {
                    scope: r.get(0)?,
                    key_name: r.get(1)?,
                    blake3_tag: r.get(2)?,
                    updated_at: r.get(3)?,
                });
            }
        }
        Ok(out)
    }

    /// Delete a secret from `(scope, key_name)` inside a `BEGIN IMMEDIATE` transaction.
    pub fn delete_secret(&self, scope: &str, key_name: &str) -> Result<bool> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "DELETE FROM scoped_secrets WHERE scope = ?1 AND key_name = ?2",
            params![scope, key_name],
        )?;
        tx.commit()?;
        Ok(changed > 0)
    }

    /// Record a stream redaction event when `FaradayRedactor` intercepts a secret in child stdout/stderr.
    pub fn record_redaction_event(
        &self,
        scope: &str,
        command: &str,
        stream: &str,
        key_name: &str,
        encoding_matched: &str,
        blake3_tag: &str,
    ) -> Result<()> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO redaction_audit_log (timestamp, scope, command, stream, key_name, encoding_matched, blake3_tag)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                Utc::now().to_rfc3339(),
                scope,
                command,
                stream,
                key_name,
                encoding_matched,
                blake3_tag
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// List all recorded stream redaction events in chronological order.
    pub fn list_redaction_events(&self) -> Result<Vec<RedactionAuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, scope, command, stream, key_name, encoding_matched, blake3_tag
             FROM redaction_audit_log ORDER BY id DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(RedactionAuditEvent {
                id: r.get(0)?,
                timestamp: r.get(1)?,
                scope: r.get(2)?,
                command: r.get(3)?,
                stream: r.get(4)?,
                key_name: r.get(5)?,
                encoding_matched: r.get(6)?,
                blake3_tag: r.get(7)?,
            });
        }
        Ok(out)
    }
}

/// Resolve the default `Faraday` SQLite vault path (`%LOCALAPPDATA%\faraday\faraday.db` or `~/.local/share/faraday/faraday.db`).
pub fn default_vault_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("FARADAY_DB_PATH") {
        return PathBuf::from(override_path);
    }
    let base = dirs::data_local_dir()
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("faraday").join("faraday.db")
}

/// Enforce owner-only ACLs on the vault directory, `db_path`, and SQLite WAL sidecar files (`-wal` and `-shm`).
pub fn enforce_vault_and_sidecar_acls(db_path: &Path) -> Result<()> {
    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
        && parent.exists()
    {
        enforce_owner_only_acl(parent, true)?;
    }
    if db_path.exists() {
        enforce_owner_only_acl(db_path, false)?;
    }

    let db_os = db_path.as_os_str();
    for suffix in ["-wal", "-shm"] {
        let mut sidecar_os = db_os.to_os_string();
        sidecar_os.push(suffix);
        let sidecar_path = PathBuf::from(sidecar_os);
        if sidecar_path.exists() {
            enforce_owner_only_acl(&sidecar_path, false)?;
        }
    }
    Ok(())
}

/// Enforce strict owner-only filesystem ACLs (`icacls /inheritance:r` on Windows, `0700`/`0600` on Unix)
/// and fail closed if permission application fails (`CWE-732`).
pub fn enforce_owner_only_acl(path: &Path, is_dir: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("failed to set mode {:o} on {}", mode, path.display()))?;
        let applied = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if applied != mode {
            return Err(anyhow!(
                "effective Unix mode {:o} != expected {:o} on {}",
                applied,
                mode,
                path.display()
            ));
        }
    }

    #[cfg(windows)]
    {
        let principal = resolve_windows_owner_principal()?;
        let grant_spec = if is_dir {
            format!("{principal}:(OI)(CI)F")
        } else {
            format!("{principal}:F")
        };
        let output = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&grant_spec)
            .output()
            .with_context(|| format!("failed to execute icacls on {}", path.display()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "icacls failed to enforce owner-only ACL on {} (status={}): {} {}",
                path.display(),
                output.status,
                stdout.trim(),
                stderr.trim()
            ));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn resolve_windows_owner_principal() -> Result<String> {
    if let Ok(out) = std::process::Command::new("whoami").output()
        && out.status.success()
    {
        let who = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !who.is_empty() {
            return Ok(who);
        }
    }
    if let Ok(username) = std::env::var("USERNAME") {
        let trimmed = username.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(anyhow!(
        "Unable to resolve Windows owner principal via `whoami` or `USERNAME` for ACL enforcement"
    ))
}
