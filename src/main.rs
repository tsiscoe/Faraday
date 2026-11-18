//! Entrypoint for the `faraday` binary (**Faraday** Zero-Disk Process Secret Injector & Live Redaction Cage).

#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use faraday_cage::{
    cage::run_caged_process,
    cli::{Cli, Commands},
    dotenv::{load_dotenv_file, shred_file_zero_fill},
    tui::{FaradayTuiApp, run_interactive_tui},
    vault::{FaradayVault, default_vault_path},
};
use zeroize::Zeroize;

const KEYRING_SERVICE: &str = "faraday-secret-cage";
const KEYRING_USER: &str = "master-vault";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.clone().unwrap_or_else(default_vault_path);
    let mut passphrase = resolve_passphrase(&cli)?;

    let vault = FaradayVault::open_with_passphrase(&db_path, passphrase.as_bytes(), false)?;
    passphrase.zeroize();

    match cli.command {
        Commands::Init => {
            let secrets = vault.list_secret_metadata(None)?;
            println!("Faraday v0.1.0 Zero-Disk Secret Vault Initialized");
            println!("  Vault Path:        {}", vault.db_path().display());
            println!("  Stored Secrets:    {}", secrets.len());
            println!("  Envelope Mode:     Argon2id + HKDF-SHA256 + Two-Tier XChaCha20-Poly1305");
        }

        Commands::Set { scope, key, value } => {
            let mut secret_val = match value {
                Some(v) => v,
                None => rpassword::prompt_password(format!("Enter secret for {scope}::{key}: "))
                    .context("failed to read secret value from terminal")?,
            };
            let meta = vault.set_secret(&scope, &key, &secret_val)?;
            secret_val.zeroize();
            println!(
                "[Faraday SEALED] scope={} key={} tag={} updated_at={}",
                meta.scope, meta.key_name, meta.blake3_tag, meta.updated_at
            );
        }

        Commands::Get { scope, key, reveal } => {
            let Some(sec) = vault.get_secret(&scope, &key)? else {
                return Err(anyhow!(
                    "Secret '{scope}::{key}' not found in Faraday vault"
                ));
            };
            if reveal {
                println!("{}", sec.value);
            } else {
                println!(
                    "[Faraday MASKED] scope={} key={} tag={} (pass --reveal to print plaintext)",
                    sec.scope, sec.key_name, sec.blake3_tag
                );
            }
        }

        Commands::List { scope, json } => {
            let items = vault.list_secret_metadata(scope.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                println!("FARADAY ENCRYPTED VAULT // {} SECRETS", items.len());
                for item in items {
                    println!(
                        "  [{:<10}] {:<28} -> tag:{} ({})",
                        item.scope, item.key_name, item.blake3_tag, item.updated_at
                    );
                }
            }
        }

        Commands::Rm { scope, key } => {
            if vault.delete_secret(&scope, &key)? {
                println!("[Faraday REMOVED] scope={scope} key={key}");
            } else {
                eprintln!("[Faraday MISS] Secret '{scope}::{key}' was not present");
                std::process::exit(1);
            }
        }

        Commands::Import { scope, file, shred } => {
            let mut pairs = load_dotenv_file(&file)?;
            let imported = vault.import_secrets_atomic(&scope, &pairs)?;
            for (k, v) in &mut pairs {
                k.zeroize();
                v.zeroize();
            }
            println!(
                "[Faraday IMPORTED] {} secrets into scope '{}' from {}",
                imported.len(),
                scope,
                file.display()
            );
            if shred {
                let bytes_wiped = shred_file_zero_fill(&file)?;
                println!(
                    "[Faraday SHREDDED] Overwrote {} bytes with 0x00 and unlinked {}",
                    bytes_wiped,
                    file.display()
                );
            }
        }

        Commands::Run {
            scope,
            isolate_env,
            cmd,
        } => {
            let exit_code = run_caged_process(&vault, &scope, &cmd, isolate_env).await?;
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }

        Commands::Audit { json } => {
            let events = vault.list_redaction_events()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                println!(
                    "FARADAY REDACTION AUDIT // {} INTERCEPTED LEAKS",
                    events.len()
                );
                for ev in events {
                    println!(
                        "  [#{:<4} {:<6}] {}::{} ({}) tag:{} in `{}`",
                        ev.id,
                        ev.stream,
                        ev.scope,
                        ev.key_name,
                        ev.encoding_matched,
                        ev.blake3_tag,
                        ev.command
                    );
                }
            }
        }

        Commands::Tui => {
            let secrets = vault.list_secret_metadata(None).unwrap_or_default();
            let events = vault.list_redaction_events().unwrap_or_default();
            let app = FaradayTuiApp::new(vault.db_path().display().to_string(), secrets, events);
            run_interactive_tui(app)?;
        }
    }

    Ok(())
}

fn resolve_passphrase(cli: &Cli) -> Result<String> {
    if let Some(p) = &cli.passphrase
        && !p.is_empty()
    {
        if cli.keyring
            && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        {
            let _ = entry.set_password(p);
        }
        return Ok(p.clone());
    }

    if cli.keyring
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        && let Ok(saved) = entry.get_password()
        && !saved.is_empty()
    {
        return Ok(saved);
    }

    let prompt_pass = rpassword::prompt_password("Faraday Vault Master Passphrase: ")
        .context("failed to read passphrase from terminal")?;
    if prompt_pass.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty"));
    }

    if cli.keyring
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
    {
        let _ = entry.set_password(&prompt_pass);
    }

    Ok(prompt_pass)
}
