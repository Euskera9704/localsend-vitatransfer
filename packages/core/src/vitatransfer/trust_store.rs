use std::fs::{
    self,
    OpenOptions,
};
use std::io::Write;
use std::path::PathBuf;

use anyhow::{
    bail,
    Context,
    Result,
};

const PUBLIC_KEY_SIZE: usize = 32;

fn identity_directory() -> Result<PathBuf> {
    let user_profile =
        std::env::var(
            "USERPROFILE"
        )
        .context(
            "USERPROFILE environment variable is missing"
        )?;

    Ok(
        PathBuf::from(
            user_profile
        )
        .join(
            ".vitafasttransfer"
        )
    )
}

pub fn trust_store_path() -> Result<PathBuf> {
    Ok(
        identity_directory()?
            .join(
                "trusted_vitas.dat"
            )
    )
}

pub fn is_trusted(
    public_key: &[u8; 32],
) -> Result<bool> {
    let path =
        trust_store_path()?;

    if !path.exists() {
        return Ok(false);
    }

    let data =
        fs::read(
            &path
        )
        .with_context(|| {
            format!(
                "Could not read VitaTransfer trust store at {}",
                path.display()
            )
        })?;

    if data.len()
        % PUBLIC_KEY_SIZE
        != 0
    {
        bail!(
            "VitaTransfer trust store is corrupted: {} bytes",
            data.len()
        );
    }

    for stored_key in
        data.chunks_exact(
            PUBLIC_KEY_SIZE
        )
    {
        if stored_key
            == public_key
        {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn add_trusted(
    public_key: &[u8; 32],
) -> Result<bool> {
    if is_trusted(
        public_key
    )? {
        return Ok(false);
    }

    let directory =
        identity_directory()?;

    fs::create_dir_all(
        &directory
    )
    .with_context(|| {
        format!(
            "Could not create VitaTransfer identity directory at {}",
            directory.display()
        )
    })?;

    let path =
        trust_store_path()?;

    let mut file =
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(
                &path
            )
            .with_context(|| {
                format!(
                    "Could not open VitaTransfer trust store at {}",
                    path.display()
                )
            })?;

    file.write_all(
        public_key
    )
    .with_context(|| {
        format!(
            "Could not save trusted Vita identity to {}",
            path.display()
        )
    })?;

    file.flush()
        .context(
            "Could not flush VitaTransfer trust store"
        )?;

    Ok(true)
}