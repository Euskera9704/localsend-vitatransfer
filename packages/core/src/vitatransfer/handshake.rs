use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};
use tokio::net::TcpStream;
use x25519_dalek::{
    EphemeralSecret,
    PublicKey,
};

use super::identity::fingerprint;

pub struct HelloExchange {
    pub ephemeral_secret: EphemeralSecret,

    pub vita_identity_public: [u8; 32],

    pub vita_ephemeral_public: [u8; 32],
}

pub async fn exchange_hello(
    stream: &mut TcpStream,
    signing_key: &SigningKey,
) -> Result<HelloExchange> {
    /*
     * Identidad permanente del iniciador.
     */
    let identity_public =
        signing_key.verifying_key().to_bytes();

    /*
     * X25519 efímero para ESTA sesión.
     */
    let ephemeral_secret =
        EphemeralSecret::random();

    let ephemeral_public =
        PublicKey::from(
            &ephemeral_secret
        );

    /*
     * Exactamente el mismo orden que
     * nuestro Python:
     *
     * 1. identidad Ed25519 PC/remoto
     * 2. pública X25519 efímera
     */
    stream
        .write_all(
            &identity_public
        )
        .await
        .context(
            "Could not send initiator Ed25519 identity",
        )?;

    stream
        .write_all(
            ephemeral_public.as_bytes()
        )
        .await
        .context(
            "Could not send initiator X25519 public key",
        )?;

    /*
     * Vita responde:
     *
     * 1. identidad Ed25519 Vita
     * 2. pública X25519 efímera Vita
     */
    let mut vita_identity_public =
        [0u8; 32];

    stream
        .read_exact(
            &mut vita_identity_public
        )
        .await
        .context(
            "Could not receive Vita Ed25519 identity",
        )?;

    let mut vita_ephemeral_public =
        [0u8; 32];

    stream
        .read_exact(
            &mut vita_ephemeral_public
        )
        .await
        .context(
            "Could not receive Vita X25519 public key",
        )?;

    println!(
        "Initiator identity: {}",
        fingerprint(
            &identity_public
        )
    );

    println!(
        "Vita identity:      {}",
        fingerprint(
            &vita_identity_public
        )
    );

    Ok(
        HelloExchange {
            ephemeral_secret,
            vita_identity_public,
            vita_ephemeral_public,
        }
    )
}