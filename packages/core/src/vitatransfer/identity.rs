use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const IDENTITY_SEED_SIZE: usize = 32;

pub fn load_existing_identity() -> Result<SigningKey> {
    let user_profile = std::env::var("USERPROFILE")
        .context("USERPROFILE environment variable is missing")?;

    let path = PathBuf::from(user_profile)
        .join(".vitafasttransfer")
        .join("identity_ed25519.seed");

    let seed = fs::read(&path).with_context(|| {
        format!(
            "Could not read existing VitaTransfer identity at {}",
            path.display()
        )
    })?;

    if seed.len() != IDENTITY_SEED_SIZE {
        bail!(
            "VitaTransfer identity seed has invalid size: {} bytes",
            seed.len()
        );
    }

    let seed_array: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid Ed25519 seed"))?;

    Ok(SigningKey::from_bytes(&seed_array))
}

pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);

    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}