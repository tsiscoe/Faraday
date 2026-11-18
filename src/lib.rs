//! **Faraday** (`faraday-cage`) — Zero-Disk Process Secret Injector & Live 4-Encoding
//! Stdout/Stderr Leak Redaction Cage (`Argon2id` + Two-Tier `XChaCha20-Poly1305` + SIMD `Aho-Corasick`).
//!
//! Enforces `#![forbid(unsafe_code)]` across the entire crate.

#![forbid(unsafe_code)]

pub mod cage;
pub mod cli;
pub mod crypto;
pub mod dotenv;
pub mod tui;
pub mod vault;
