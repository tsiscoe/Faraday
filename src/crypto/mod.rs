//! Cryptographic Core for **Faraday** (`faraday-cage v0.1.0`):
//! - **`Argon2id`** (`m = 64 MiB, t = 3, p = 4`) master seed derivation
//! - **`HKDF-SHA256`** domain-separated subkey expansion (`kek_key`, `mac_key`, `verifier`)
//! - **Two-Tier `XChaCha20-Poly1305` Envelope Encryption:** Every secret gets an independent
//!   CSPRNG 256-bit `DataEncryptionKey` (`DEK`) wrapped by `kek_key` with contextual AAD
//!   (`faraday-v1|<scope>|<key_name>|dek`), and the secret value is encrypted under that `DEK`
//!   with contextual AAD (`faraday-v1|<scope>|<key_name>|val`).
//! - **`constant_time_eq_32`** (`CWE-208`) and **`ZeroizeOnDrop`** (`CWE-316`).

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const XNONCE_LEN: usize = 24;

/// 256-bit Master Seed derived from user passphrase via `Argon2id`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed([u8; KEY_LEN]);

/// Domain-separated 256-bit subkeys expanded from [`MasterSeed`] via `HKDF-SHA256`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultSubkeys {
    /// Key-Encryption-Key (`KEK`) wrapping per-secret 256-bit DEKs (`faraday-v1-kek-key`).
    pub kek_key: [u8; KEY_LEN],
    /// Keyed `BLAKE3` blind-index & fingerprint key (`faraday-v1-mac-key`).
    pub mac_key: [u8; KEY_LEN],
    /// Constant-time passphrase verifier digest (`faraday-v1-verifier`).
    pub verifier: [u8; KEY_LEN],
}

/// Zeroizing decrypted plaintext buffer.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecryptedSecret(pub Vec<u8>);

impl DecryptedSecret {
    pub fn into_utf8_string(self) -> Result<String> {
        String::from_utf8(self.0.clone())
            .map_err(|_| anyhow!("decrypted secret is not valid UTF-8"))
    }
}

/// Two-tier encrypted secret envelope stored in `faraday.db`.
#[derive(Debug, Clone)]
pub struct TwoTierEnvelope {
    pub wrapped_dek: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl MasterSeed {
    /// Derive a 256-bit `MasterSeed` using production `Argon2id` parameters (`64 MiB, t=3, p=4`).
    pub fn derive_from_passphrase(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN))
            .map_err(|e| anyhow!("invalid Argon2id params: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Fast `Argon2id` derivation (`8 MiB, t=1, p=1`) strictly for unit/property test suites.
    pub fn derive_fast_for_test(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(8 * 1024, 1, 1, Some(KEY_LEN))
            .map_err(|e| anyhow!("invalid test Argon2id params: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("test Argon2id derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Expand `kek_key`, `mac_key`, and `verifier` via `HKDF-SHA256`.
    pub fn derive_subkeys(&self, salt: &[u8; SALT_LEN]) -> Result<VaultSubkeys> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut kek_key = [0u8; KEY_LEN];
        let mut mac_key = [0u8; KEY_LEN];
        let mut verifier = [0u8; KEY_LEN];

        hk.expand(b"faraday-v1-kek-key", &mut kek_key)
            .map_err(|_| anyhow!("HKDF expand failed for kek_key"))?;
        hk.expand(b"faraday-v1-mac-key", &mut mac_key)
            .map_err(|_| anyhow!("HKDF expand failed for mac_key"))?;
        hk.expand(b"faraday-v1-verifier", &mut verifier)
            .map_err(|_| anyhow!("HKDF expand failed for verifier"))?;

        Ok(VaultSubkeys {
            kek_key,
            mac_key,
            verifier,
        })
    }
}

/// Generate a fresh 128-bit CSPRNG salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Constant-time 32-byte equality comparison (`CWE-208`).
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Encrypt `plaintext` under `key` using `XChaCha20-Poly1305` (24-byte random nonce prepended) and `aad`.
pub fn aead_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;

    let mut out = Vec::with_capacity(XNONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt `nonce_and_ciphertext` under `key` and verify `aad`.
pub fn aead_decrypt(
    key: &[u8; KEY_LEN],
    nonce_and_ciphertext: &[u8],
    aad: &[u8],
) -> Result<DecryptedSecret> {
    if nonce_and_ciphertext.len() < XNONCE_LEN + 16 {
        return Err(anyhow!("ciphertext too short for XChaCha20-Poly1305"));
    }
    let (nonce_bytes, ct) = nonce_and_ciphertext.split_at(XNONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| anyhow!("XChaCha20-Poly1305 authentication or AAD verification failed"))?;

    Ok(DecryptedSecret(pt))
}

/// Seal a secret using Two-Tier envelope encryption: generates a fresh 256-bit `DEK`, encrypts
/// `plaintext` under `DEK` with `val_aad`, wraps `DEK` under `kek_key` with `dek_aad`, and
/// zeroizes `DEK` on the stack before returning.
pub fn seal_two_tier_secret(
    kek_key: &[u8; KEY_LEN],
    scope: &str,
    key_name: &str,
    plaintext: &[u8],
) -> Result<TwoTierEnvelope> {
    let mut dek = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut dek);

    let dek_aad = build_envelope_aad(scope, key_name, "dek");
    let val_aad = build_envelope_aad(scope, key_name, "val");

    let wrapped_dek = aead_encrypt(kek_key, &dek, &dek_aad);
    let ciphertext = aead_encrypt(&dek, plaintext, &val_aad);
    dek.zeroize();

    Ok(TwoTierEnvelope {
        wrapped_dek: wrapped_dek?,
        ciphertext: ciphertext?,
    })
}

/// Open a Two-Tier secret envelope, verifying both `dek_aad` and `val_aad`, and zeroizing the
/// intermediate `DEK` immediately.
pub fn open_two_tier_secret(
    kek_key: &[u8; KEY_LEN],
    scope: &str,
    key_name: &str,
    wrapped_dek: &[u8],
    ciphertext: &[u8],
) -> Result<DecryptedSecret> {
    let dek_aad = build_envelope_aad(scope, key_name, "dek");
    let val_aad = build_envelope_aad(scope, key_name, "val");

    let unwrapped = aead_decrypt(kek_key, wrapped_dek, &dek_aad)?;
    let mut dek: [u8; KEY_LEN] = unwrapped
        .0
        .clone()
        .try_into()
        .map_err(|_| anyhow!("corrupted 256-bit DEK length"))?;

    let pt_res = aead_decrypt(&dek, ciphertext, &val_aad);
    dek.zeroize();
    pt_res
}

fn build_envelope_aad(scope: &str, key_name: &str, field: &str) -> Vec<u8> {
    format!("faraday-v1|{scope}|{key_name}|{field}").into_bytes()
}

/// Compute a keyed `BLAKE3` short hex fingerprint (`8` hex chars) for redaction placeholders
/// (`[FARADAY:REDACTED:<KEY>:<TAG>]`) so operators can correlate which secret value was scrubbed
/// without exposing the secret.
pub fn compute_secret_short_tag(
    mac_key: &[u8; KEY_LEN],
    scope: &str,
    key_name: &str,
    value: &str,
) -> String {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(b"faraday-v1-secret-tag|");
    hasher.update(scope.as_bytes());
    hasher.update(b"|");
    hasher.update(key_name.as_bytes());
    hasher.update(b"|");
    hasher.update(value.as_bytes());
    let full_hex = hasher.finalize().to_hex();
    full_hex.as_str()[..8].to_string()
}
