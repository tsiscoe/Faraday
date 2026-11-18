//! `.env` File Harvester, Parser & Zero-Fill Cryptographic Shredder.
//!
//! Security Invariants:
//! - Enforces `MAX_DOTENV_BYTES = 16 MiB` (`CWE-400`).
//! - Parses `KEY=VAL`, `export KEY=VAL`, single-quoted `'...'`, double-quoted `"..."` (with `\n`,
//!   `\r`, `\t`, `\"`, `\\` escapes), and strips unquoted inline `#` comments.
//! - When `--shred` is enabled (`shred_file_zero_fill`), overwrites the entire file byte-for-byte
//!   with `0x00`, flushes to physical storage via `File::sync_all()`, and unlinks the file.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use zeroize::Zeroize;

/// Maximum permitted `.env` file size (16 MiB).
pub const MAX_DOTENV_BYTES: u64 = 16 * 1024 * 1024;

/// Parse a `.env`-formatted text buffer into ordered `(key, value)` pairs.
pub fn parse_dotenv_str(content: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let without_export = if let Some(rest) = trimmed.strip_prefix("export ") {
            rest.trim_start()
        } else {
            trimmed
        };

        let Some(eq_pos) = without_export.find('=') else {
            return Err(anyhow!(
                "Malformed .env entry at line {line_no}: missing '=' delimiter"
            ));
        };

        let key = without_export[..eq_pos].trim().to_string();
        if key.is_empty() {
            return Err(anyhow!("Malformed .env entry at line {line_no}: empty key"));
        }

        let raw_val = without_export[eq_pos + 1..].trim();
        let val = parse_dotenv_value(raw_val, line_no)?;
        out.push((key, val));
    }

    Ok(out)
}

fn parse_dotenv_value(raw_val: &str, line_no: usize) -> Result<String> {
    if raw_val.is_empty() {
        return Ok(String::new());
    }

    if let Some(inner) = raw_val.strip_prefix('"') {
        let Some(end_quote) = find_unescaped_double_quote(inner) else {
            return Err(anyhow!(
                "Unterminated double-quoted value in .env at line {line_no}"
            ));
        };
        let quoted_body = &inner[..end_quote];
        return Ok(unescape_double_quoted(quoted_body));
    }

    if let Some(inner) = raw_val.strip_prefix('\'') {
        let Some(end_quote) = inner.find('\'') else {
            return Err(anyhow!(
                "Unterminated single-quoted value in .env at line {line_no}"
            ));
        };
        return Ok(inner[..end_quote].to_string());
    }

    // Unquoted value: strip trailing inline `#` comment if preceded by whitespace
    let mut clean = raw_val;
    for (i, _) in raw_val.match_indices('#') {
        if i > 0 && raw_val.as_bytes()[i - 1].is_ascii_whitespace() {
            clean = raw_val[..i].trim_end();
            break;
        }
    }
    Ok(clean.to_string())
}

fn find_unescaped_double_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn unescape_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Read and parse a `.env` file from disk (enforcing [`MAX_DOTENV_BYTES`]), zeroizing the raw
/// file buffer before returning the parsed `(key, value)` pairs.
pub fn load_dotenv_file(path: &Path) -> Result<Vec<(String, String)>> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("failed to stat .env file {}", path.display()))?;
    if meta.len() > MAX_DOTENV_BYTES {
        return Err(anyhow!(
            ".env file {} exceeds maximum size limit ({} bytes > {MAX_DOTENV_BYTES})",
            path.display(),
            meta.len()
        ));
    }

    let mut raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read .env file {}", path.display()))?;
    let parsed = parse_dotenv_str(&raw);
    raw.zeroize();
    parsed
}

/// Overwrite `path` on disk with `0x00` bytes (`sync_all`) and then remove it (`--shred`).
pub fn shred_file_zero_fill(path: &Path) -> Result<u64> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("failed to stat file for shredding: {}", path.display()))?;
    let len = meta.len();

    {
        let mut f = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open {} for zero-fill shred", path.display()))?;
        f.seek(SeekFrom::Start(0))?;

        let chunk = [0u8; 8192];
        let mut remaining = len;
        while remaining > 0 {
            let to_write = remaining.min(chunk.len() as u64) as usize;
            f.write_all(&chunk[..to_write])?;
            remaining -= to_write as u64;
        }
        f.sync_all()?;
    }

    std::fs::remove_file(path)
        .with_context(|| format!("failed to unlink shredded file {}", path.display()))?;
    Ok(len)
}
