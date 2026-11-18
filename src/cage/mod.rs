//! Zero-Disk Process Secret Injector & Live 4-Encoding Stdout/Stderr Leak Redaction Cage (`WP-FARADAY-3`).
//!
//! Security Architecture:
//! - **4-Encoding SIMD `Aho-Corasick` (`LeftmostLongest`) Redactor (`FaradayRedactor`):**
//!   For every secret with length `>= MIN_REDACT_SECRET_LEN` (`4` bytes), builds patterns for:
//!   1. `raw`: Exact plaintext secret string
//!   2. `base64`: Standard Base64 (`STANDARD`) and URL-safe Base64 (`URL_SAFE_NO_PAD`)
//!   3. `hex`: Lowercase and uppercase hex encoding (`hex::encode`)
//!   4. `url`: Percent-encoded form (`url_percent_encode_rfc3986`)
//!
//!   Replaces any match in child `stdout` or `stderr` with `[FARADAY:REDACTED:<KEY_NAME>:<BLAKE3_TAG>]`.
//! - **Cancel-Safe Bounded Line Reader (`CancelSafeLineReader<R>`):**
//!   Preserves partial line chunks across cancelled `tokio::select!` polls (`[CODEX-P1-01]`) and
//!   enforces `MAX_STREAM_LINE_BYTES = 4 MiB` (`CWE-770`).
//! - **Child Environment Scrubbing & Ephemeral Injection:**
//!   Strips `FARADAY_PASSPHRASE`, `FARADAY_DB_PATH`, `LOOM_*`, and `SIGNET_*` from the child's
//!   environment (`[HORDE-01]`), supports `--isolate-env` (`cmd.env_clear()` + `SAFE_OS_ENV_ALLOWLIST`),
//!   injects decrypted scoped secrets, and immediately zeroizes the parent's plaintext copies after `spawn()`.

use std::fmt::Write as _;
use std::time::Duration;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use anyhow::{Context, Result, anyhow};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::Command,
    time::timeout,
};
use zeroize::Zeroize;

use crate::vault::{DecryptedScopedSecret, FaradayVault};

/// Minimum secret length eligible for stream redaction (`4` bytes) to avoid false-positive single-char matches.
pub const MIN_REDACT_SECRET_LEN: usize = 4;
/// Maximum line length buffered before forced chunk flush (`4 MiB`).
pub const MAX_STREAM_LINE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum duration allowed for a single stdio write + flush (`10s`).
pub const MAX_STDIO_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Control environment variables unconditionally stripped from child processes so a child cannot
/// unlock `faraday.db` (`[HORDE-01]`).
pub const SCRUBBED_CONTROL_ENV_KEYS: &[&str] = &[
    "FARADAY_PASSPHRASE",
    "FARADAY_DB_PATH",
    "LOOM_PASSPHRASE",
    "LOOM_DB_PATH",
    "SIGNET_PASSPHRASE",
    "SIGNET_TOKEN",
    "SIGNET_DB_PATH",
];

/// Safe baseline OS environment variables preserved when `--isolate-env` is active (`[CODEX-P1-04]`).
pub const SAFE_OS_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "COMMONPROGRAMFILES",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "COLORTERM",
    "TZ",
    "RUST_LOG",
    "RUST_BACKTRACE",
];

/// A single intercepted secret hit during a line redaction pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedHit {
    pub key_name: String,
    pub encoding: String,
    pub blake3_tag: String,
}

/// Result of redacting a single line or chunk through [`FaradayRedactor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedLineOutcome {
    pub text: String,
    pub hits: Vec<RedactedHit>,
}

#[derive(Clone)]
struct PatternRule {
    needle: String,
    key_name: String,
    encoding: String,
    blake3_tag: String,
    replacement: String,
}

impl Drop for PatternRule {
    fn drop(&mut self) {
        self.needle.zeroize();
    }
}

/// Multi-encoding SIMD `Aho-Corasick` (`LeftmostLongest`) stream redactor.
pub struct FaradayRedactor {
    ac: Option<AhoCorasick>,
    rules: Vec<PatternRule>,
}

impl FaradayRedactor {
    /// Build a `FaradayRedactor` over all decrypted secrets in `secrets`.
    pub fn new(secrets: &[DecryptedScopedSecret]) -> Self {
        let mut rules: Vec<PatternRule> = Vec::new();

        for sec in secrets {
            let val = sec.value.as_str();
            if val.len() < MIN_REDACT_SECRET_LEN {
                continue;
            }
            let replacement = format!("[FARADAY:REDACTED:{}:{}]", sec.key_name, sec.blake3_tag);

            // 1. Raw plaintext
            Self::push_unique_rule(
                &mut rules,
                val.to_string(),
                &sec.key_name,
                "raw",
                &sec.blake3_tag,
                &replacement,
            );

            // 2. Standard Base64 & URL-Safe Base64
            let b64_std = STANDARD.encode(val.as_bytes());
            Self::push_unique_rule(
                &mut rules,
                b64_std,
                &sec.key_name,
                "base64",
                &sec.blake3_tag,
                &replacement,
            );

            let b64_url = URL_SAFE_NO_PAD.encode(val.as_bytes());
            Self::push_unique_rule(
                &mut rules,
                b64_url,
                &sec.key_name,
                "base64url",
                &sec.blake3_tag,
                &replacement,
            );

            // 3. Lowercase & Uppercase Hex
            let hex_lower = hex::encode(val.as_bytes());
            let hex_upper = hex_lower.to_ascii_uppercase();
            Self::push_unique_rule(
                &mut rules,
                hex_lower,
                &sec.key_name,
                "hex",
                &sec.blake3_tag,
                &replacement,
            );
            Self::push_unique_rule(
                &mut rules,
                hex_upper,
                &sec.key_name,
                "hex",
                &sec.blake3_tag,
                &replacement,
            );

            // 4. URL percent-encoded (RFC 3986 unreserved: A-Z a-z 0-9 - _ . ~)
            let url_enc = url_percent_encode_rfc3986(val);
            if url_enc != val {
                Self::push_unique_rule(
                    &mut rules,
                    url_enc,
                    &sec.key_name,
                    "url",
                    &sec.blake3_tag,
                    &replacement,
                );
            }
        }

        // Sort longest needle first so LeftmostLongest prefers longer multi-secret or full encodings
        rules.sort_by_key(|a| std::cmp::Reverse(a.needle.len()));

        let ac = if rules.is_empty() {
            None
        } else {
            let needles: Vec<&str> = rules.iter().map(|r| r.needle.as_str()).collect();
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&needles)
                .ok()
        };

        Self { ac, rules }
    }

    fn push_unique_rule(
        rules: &mut Vec<PatternRule>,
        needle: String,
        key_name: &str,
        encoding: &str,
        blake3_tag: &str,
        replacement: &str,
    ) {
        if needle.len() < MIN_REDACT_SECRET_LEN {
            return;
        }
        if rules.iter().any(|r| r.needle == needle) {
            return;
        }
        rules.push(PatternRule {
            needle,
            key_name: key_name.to_string(),
            encoding: encoding.to_string(),
            blake3_tag: blake3_tag.to_string(),
            replacement: replacement.to_string(),
        });
    }

    /// Redact any occurrence of any registered secret (across all 4 encodings) in `input`.
    pub fn redact_line(&self, input: &str) -> RedactedLineOutcome {
        let Some(ac) = &self.ac else {
            return RedactedLineOutcome {
                text: input.to_string(),
                hits: Vec::new(),
            };
        };

        let mut out = String::with_capacity(input.len());
        let mut hits = Vec::new();
        let mut last_end = 0usize;

        for mat in ac.find_iter(input) {
            out.push_str(&input[last_end..mat.start()]);
            let rule = &self.rules[mat.pattern().as_usize()];
            out.push_str(&rule.replacement);
            hits.push(RedactedHit {
                key_name: rule.key_name.clone(),
                encoding: rule.encoding.clone(),
                blake3_tag: rule.blake3_tag.clone(),
            });
            last_end = mat.end();
        }
        out.push_str(&input[last_end..]);

        RedactedLineOutcome { text: out, hits }
    }
}

fn url_percent_encode_rfc3986(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

/// Result of reading a single bounded line from an async stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedLineResult {
    Line(String),
    Oversized { max_bytes: usize },
    Eof,
}

/// Cancel-safe buffered line reader (`[CODEX-P1-01]`).
/// Retains `buf` inside the struct so cancellation inside `tokio::select!` never loses partial lines.
pub struct CancelSafeLineReader<R> {
    reader: R,
    buf: Vec<u8>,
    oversized: bool,
    max_bytes: usize,
}

impl<R> CancelSafeLineReader<R>
where
    R: AsyncBufRead + Unpin,
{
    pub fn new(reader: R, max_bytes: usize) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            oversized: false,
            max_bytes,
        }
    }

    pub async fn next_line(&mut self) -> Result<BoundedLineResult> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                if self.buf.is_empty() && !self.oversized {
                    return Ok(BoundedLineResult::Eof);
                }
                let was_oversized = std::mem::replace(&mut self.oversized, false);
                let taken = std::mem::take(&mut self.buf);
                if was_oversized {
                    return Ok(BoundedLineResult::Oversized {
                        max_bytes: self.max_bytes,
                    });
                }
                return Ok(BoundedLineResult::Line(Self::decode_lossy(taken)));
            }

            if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
                let chunk = &available[..newline_pos];
                if !self.oversized {
                    if self.buf.len() + chunk.len() > self.max_bytes {
                        self.oversized = true;
                        self.buf.clear();
                    } else {
                        self.buf.extend_from_slice(chunk);
                    }
                }
                self.reader.consume(newline_pos + 1);
                let was_oversized = std::mem::replace(&mut self.oversized, false);
                let taken = std::mem::take(&mut self.buf);
                if was_oversized {
                    return Ok(BoundedLineResult::Oversized {
                        max_bytes: self.max_bytes,
                    });
                }
                return Ok(BoundedLineResult::Line(Self::decode_lossy(taken)));
            } else {
                let chunk_len = available.len();
                if !self.oversized {
                    if self.buf.len() + chunk_len > self.max_bytes {
                        self.oversized = true;
                        self.buf.clear();
                    } else {
                        self.buf.extend_from_slice(available);
                    }
                }
                self.reader.consume(chunk_len);
            }
        }
    }

    fn decode_lossy(mut buf: Vec<u8>) -> String {
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        String::from_utf8_lossy(&buf).into_owned()
    }
}

/// Compute control environment keys (`FARADAY_*`, `LOOM_*`, `SIGNET_*`) that must be stripped
/// before spawning a child process (`[HORDE-01]`).
pub fn compute_scrubbed_control_env_keys<I, K>(env_keys: I) -> Vec<String>
where
    I: IntoIterator<Item = K>,
    K: AsRef<str>,
{
    let mut to_remove: Vec<String> = SCRUBBED_CONTROL_ENV_KEYS
        .iter()
        .map(|&s| s.to_string())
        .collect();

    for k in env_keys {
        let key_str = k.as_ref();
        let upper = key_str.to_ascii_uppercase();
        if (upper.starts_with("FARADAY_")
            || upper.starts_with("LOOM_")
            || upper.starts_with("SIGNET_"))
            && !to_remove.contains(&key_str.to_string())
        {
            to_remove.push(key_str.to_string());
        }
    }
    to_remove
}

/// Build a `tokio::process::Command` with Faraday control variables stripped (or full `--isolate-env`
/// default-deny OS baseline) and the decrypted `scoped_secrets` injected directly into process memory.
pub fn build_caged_child_command(
    command_args: &[String],
    scoped_secrets: &[DecryptedScopedSecret],
    isolate_env: bool,
) -> Command {
    let mut cmd = Command::new(&command_args[0]);
    cmd.args(&command_args[1..]);
    cmd.kill_on_drop(true);

    if isolate_env {
        cmd.env_clear();
        for (k_os, v_os) in std::env::vars_os() {
            if let Some(k_str) = k_os.to_str() {
                let in_safe_baseline = SAFE_OS_ENV_ALLOWLIST
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(k_str));
                let is_control = k_str.to_ascii_uppercase().starts_with("FARADAY_")
                    || k_str.to_ascii_uppercase().starts_with("LOOM_")
                    || k_str.to_ascii_uppercase().starts_with("SIGNET_");
                if in_safe_baseline && !is_control {
                    cmd.env(k_os, v_os);
                }
            }
        }
    } else {
        let current_keys: Vec<String> = std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .collect();
        for key in compute_scrubbed_control_env_keys(&current_keys) {
            cmd.env_remove(key);
        }
    }

    for sec in scoped_secrets {
        cmd.env(&sec.key_name, &sec.value);
    }

    cmd
}

async fn write_line_with_timeout<W>(writer: &mut W, line: &str) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(MAX_STDIO_WRITE_TIMEOUT, async {
        writer.write_all(line.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| anyhow!("Stdio write timed out after {:?}", MAX_STDIO_WRITE_TIMEOUT))?
    .context("Stdio write failed")
}

/// Spawn `command_args` with `scope` secrets injected into memory, redact all `stdout` and `stderr`
/// lines through [`FaradayRedactor`], record redaction events in `vault`, and return the child's
/// exit status code (`WP-FARADAY-3`).
pub async fn run_caged_process(
    vault: &FaradayVault,
    scope: &str,
    command_args: &[String],
    isolate_env: bool,
) -> Result<i32> {
    if command_args.is_empty() {
        return Err(anyhow!("No child command specified after '--'"));
    }

    let mut secrets = vault.decrypt_scope_secrets(scope)?;
    let redactor = FaradayRedactor::new(&secrets);

    let mut child = build_caged_child_command(command_args, &secrets, isolate_env)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn child command '{}'", command_args[0]))?;

    // Immediately zeroize the parent's decrypted secret vector now that the child is spawned
    // and the Aho-Corasick automaton is compiled!
    secrets.clear();

    let child_stdout = child.stdout.take().expect("piped stdout");
    let child_stderr = child.stderr.take().expect("piped stderr");

    let mut out_reader =
        CancelSafeLineReader::new(BufReader::new(child_stdout), MAX_STREAM_LINE_BYTES);
    let mut err_reader =
        CancelSafeLineReader::new(BufReader::new(child_stderr), MAX_STREAM_LINE_BYTES);

    let mut host_stdout = tokio::io::stdout();
    let mut host_stderr = tokio::io::stderr();

    let cmd_label = command_args.join(" ");
    let mut out_eof = false;
    let mut err_eof = false;

    let stream_res: Result<()> = async {
        while !out_eof || !err_eof {
            tokio::select! {
                res = out_reader.next_line(), if !out_eof => {
                    match res? {
                        BoundedLineResult::Line(line) => {
                            let redacted = redactor.redact_line(&line);
                            for hit in &redacted.hits {
                                let _ = vault.record_redaction_event(
                                    scope,
                                    &cmd_label,
                                    "stdout",
                                    &hit.key_name,
                                    &hit.encoding,
                                    &hit.blake3_tag,
                                );
                            }
                            write_line_with_timeout(&mut host_stdout, &redacted.text).await?;
                        }
                        BoundedLineResult::Oversized { max_bytes } => {
                            let msg = format!("[FARADAY:OVERSIZED_LINE_DROPPED:>{max_bytes}_BYTES]");
                            write_line_with_timeout(&mut host_stdout, &msg).await?;
                        }
                        BoundedLineResult::Eof => {
                            out_eof = true;
                        }
                    }
                }
                res = err_reader.next_line(), if !err_eof => {
                    match res? {
                        BoundedLineResult::Line(line) => {
                            let redacted = redactor.redact_line(&line);
                            for hit in &redacted.hits {
                                let _ = vault.record_redaction_event(
                                    scope,
                                    &cmd_label,
                                    "stderr",
                                    &hit.key_name,
                                    &hit.encoding,
                                    &hit.blake3_tag,
                                );
                            }
                            write_line_with_timeout(&mut host_stderr, &redacted.text).await?;
                        }
                        BoundedLineResult::Oversized { max_bytes } => {
                            let msg = format!("[FARADAY:OVERSIZED_LINE_DROPPED:>{max_bytes}_BYTES]");
                            write_line_with_timeout(&mut host_stderr, &msg).await?;
                        }
                        BoundedLineResult::Eof => {
                            err_eof = true;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    .await;

    if stream_res.is_err() {
        let _ = child.kill().await;
    }
    let status = child
        .wait()
        .await
        .context("failed to wait on child process")?;
    stream_res?;

    Ok(status.code().unwrap_or(1))
}
