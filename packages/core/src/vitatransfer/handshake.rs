use anyhow::{
    anyhow,
    bail,
    Context,
    Result,
};
use ed25519_dalek::{
    Signature,
    Signer,
    SigningKey,
    Verifier,
    VerifyingKey,
};
use hkdf::Hkdf;
use hmac::{
    Hmac,
    KeyInit,
    Mac,
};
use sha2::{
    Digest,
    Sha256,
};
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
use super::protocol::{
    DATA_I2R_LABEL,
    DATA_R2I_LABEL,
    HKDF_INFO,
    HKDF_SALT,
    PAIR_LABEL,
    PROTOCOL_LABEL,
    SESSION_READY,
};
use super::trust_store;

type HmacSha256 = Hmac<Sha256>;

pub struct SessionKeys {
    pub session_key: [u8; 32],

    pub initiator_to_responder_key:
        [u8; 32],

    pub responder_to_initiator_key:
        [u8; 32],
}

pub struct HandshakeResult {
    pub vita_identity_public:
        [u8; 32],

    pub transcript_hash:
        [u8; 32],

    pub keys:
        SessionKeys,
}

pub struct PendingPairing {
    pub pairing_code:
        String,

    pub result:
        HandshakeResult,

    save_vita_on_success:
        bool,
}

pub enum HandshakeStatus {
    Established(
        HandshakeResult
    ),

    PairingRequired(
        PendingPairing
    ),
}

fn derive_directional_key(
    session_key: &[u8; 32],
    label: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut mac =
        HmacSha256::new_from_slice(
            session_key
        )
        .map_err(|_| {
            anyhow!(
                "Could not initialize VitaTransfer HMAC"
            )
        })?;

    mac.update(
        label
    );

    mac.update(
        transcript_hash
    );

    let result =
        mac.finalize()
            .into_bytes();

    let mut key =
        [0u8; 32];

    key.copy_from_slice(
        &result
    );

    Ok(key)
}

fn make_pairing_code(
    session_key: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> String {
    let mut hasher =
        Sha256::new();

    hasher.update(
        PAIR_LABEL
    );

    hasher.update(
        session_key
    );

    hasher.update(
        transcript_hash
    );

    let digest =
        hasher.finalize();

    let value =
        u32::from_be_bytes([
            digest[0],
            digest[1],
            digest[2],
            digest[3],
        ])
        % 1_000_000;

    format!(
        "{value:06}"
    )
}

async fn receive_session_ready(
    stream: &mut TcpStream,
) -> Result<()> {
    let mut session_ready =
        [0u8; 1];

    stream
        .read_exact(
            &mut session_ready
        )
        .await
        .context(
            "Could not receive Vita SESSION_READY"
        )?;

    if session_ready[0]
        != SESSION_READY
    {
        bail!(
            "Invalid SESSION_READY: expected 0x{:02X}, received 0x{:02X}",
            SESSION_READY,
            session_ready[0],
        );
    }

    println!(
        "SESSION_READY received: 0x{:02X}",
        session_ready[0]
    );

    Ok(())
}

pub async fn perform_handshake(
    stream: &mut TcpStream,
    signing_key: &SigningKey,
) -> Result<HandshakeStatus> {
    /*
     * =====================================================
     * IDENTIDAD PC
     * =====================================================
     */

    let identity_public =
        signing_key
            .verifying_key()
            .to_bytes();

    /*
     * =====================================================
     * X25519 EFIMERO
     * =====================================================
     */

    let ephemeral_secret =
        EphemeralSecret::random();

    let ephemeral_public =
        PublicKey::from(
            &ephemeral_secret
        );

    let ephemeral_public_bytes =
        *ephemeral_public
            .as_bytes();

    /*
     * =====================================================
     * PC -> VITA
     * =====================================================
     */

    stream
        .write_all(
            &identity_public
        )
        .await
        .context(
            "Could not send initiator Ed25519 identity"
        )?;

    stream
        .write_all(
            &ephemeral_public_bytes
        )
        .await
        .context(
            "Could not send initiator X25519 public key"
        )?;

    /*
     * =====================================================
     * VITA -> PC
     * =====================================================
     */

    let mut vita_identity_public =
        [0u8; 32];

    stream
        .read_exact(
            &mut vita_identity_public
        )
        .await
        .context(
            "Could not receive Vita Ed25519 identity"
        )?;

    let mut vita_ephemeral_public =
        [0u8; 32];

    stream
        .read_exact(
            &mut vita_ephemeral_public
        )
        .await
        .context(
            "Could not receive Vita X25519 public key"
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

    /*
     * =====================================================
     * TRANSCRIPT
     * =====================================================
     */

    let mut transcript =
        Vec::with_capacity(
            PROTOCOL_LABEL.len()
                + 32
                + 32
                + 32
                + 32
        );

    transcript.extend_from_slice(
        PROTOCOL_LABEL
    );

    transcript.extend_from_slice(
        &identity_public
    );

    transcript.extend_from_slice(
        &vita_identity_public
    );

    transcript.extend_from_slice(
        &ephemeral_public_bytes
    );

    transcript.extend_from_slice(
        &vita_ephemeral_public
    );

    let digest =
        Sha256::digest(
            &transcript
        );

    let mut transcript_hash =
        [0u8; 32];

    transcript_hash
        .copy_from_slice(
            &digest
        );

    /*
     * =====================================================
     * FIRMA PC
     * =====================================================
     */

    let pc_signature =
        signing_key.sign(
            &transcript
        );

    stream
        .write_all(
            &pc_signature
                .to_bytes()
        )
        .await
        .context(
            "Could not send PC Ed25519 signature"
        )?;

    println!(
        "PC Ed25519 signature sent."
    );

    /*
     * =====================================================
     * FIRMA VITA
     * =====================================================
     */

    let mut vita_signature_bytes =
        [0u8; 64];

    stream
        .read_exact(
            &mut vita_signature_bytes
        )
        .await
        .context(
            "Could not receive Vita Ed25519 signature"
        )?;

    let vita_verifying_key =
        VerifyingKey::from_bytes(
            &vita_identity_public
        )
        .context(
            "Vita sent an invalid Ed25519 public key"
        )?;

    let vita_signature =
        Signature::from_bytes(
            &vita_signature_bytes
        );

    vita_verifying_key
        .verify(
            &transcript,
            &vita_signature
        )
        .context(
            "Vita Ed25519 signature verification failed"
        )?;

    println!(
        "Vita Ed25519 signature: OK"
    );

    /*
     * =====================================================
     * COMPROBAR TRUST LOCAL
     * =====================================================
     *
     * Importante:
     *
     * primero verificamos la firma.
     *
     * Después comprobamos si esa identidad
     * concreta está guardada.
     */

    let vita_trusted_locally =
        trust_store::is_trusted(
            &vita_identity_public
        )?;

    if vita_trusted_locally {
        println!(
            "PC trust: Vita identity VERIFIED"
        );
    } else {
        println!(
            "PC trust: Vita identity NOT YET TRUSTED"
        );
    }

    /*
     * =====================================================
     * X25519
     * =====================================================
     */

    let vita_x25519_public =
        PublicKey::from(
            vita_ephemeral_public
        );

    let shared_secret =
        ephemeral_secret
            .diffie_hellman(
                &vita_x25519_public
            );

    println!(
        "X25519 shared secret derived."
    );

    /*
     * =====================================================
     * HKDF
     * =====================================================
     */

    let mut hkdf_info =
        Vec::with_capacity(
            HKDF_INFO.len()
                + transcript_hash.len()
        );

    hkdf_info.extend_from_slice(
        HKDF_INFO
    );

    hkdf_info.extend_from_slice(
        &transcript_hash
    );

    let hkdf =
        Hkdf::<Sha256>::new(
            Some(
                HKDF_SALT
            ),
            shared_secret
                .as_bytes(),
        );

    let mut session_key =
        [0u8; 32];

    hkdf.expand(
        &hkdf_info,
        &mut session_key
    )
    .map_err(|_| {
        anyhow!(
            "VitaTransfer HKDF expansion failed"
        )
    })?;

    println!(
        "HKDF-SHA256 session key derived."
    );

    /*
     * =====================================================
     * CLAVES DIRECCIONALES
     * =====================================================
     */

    let initiator_to_responder_key =
        derive_directional_key(
            &session_key,
            DATA_I2R_LABEL,
            &transcript_hash
        )?;

    let responder_to_initiator_key =
        derive_directional_key(
            &session_key,
            DATA_R2I_LABEL,
            &transcript_hash
        )?;

    println!(
        "Directional keys derived."
    );

    let result =
        HandshakeResult {
            vita_identity_public,
            transcript_hash,

            keys:
                SessionKeys {
                    session_key,

                    initiator_to_responder_key,

                    responder_to_initiator_key,
                },
        };

    /*
     * =====================================================
     * TRUST STATUS DE LA VITA
     * =====================================================
     */

    let mut trust_status =
        [0u8; 1];

    stream
        .read_exact(
            &mut trust_status
        )
        .await
        .context(
            "Could not receive Vita trust status"
        )?;

    match (
        vita_trusted_locally,
        trust_status[0],
    ) {
        /*
         * =================================================
         * AMBOS SE CONOCEN
         * =================================================
         */

        (
            true,
            1,
        ) => {
            println!(
                "Vita trust: PC identity VERIFIED"
            );

            println!(
                "Mutual trust: VERIFIED"
            );

            receive_session_ready(
                stream
            )
            .await?;

            Ok(
                HandshakeStatus::Established(
                    result
                )
            )
        }

        /*
         * =================================================
         * PC CONOCE VITA,
         * VITA YA NO CONOCE PC
         *
         * Re-pair normal.
         * =================================================
         */

        (
            true,
            0,
        ) => {
            println!(
                "Vita trust: PAIRING REQUIRED"
            );

            let pairing_code =
                make_pairing_code(
                    &result
                        .keys
                        .session_key,

                    &result
                        .transcript_hash,
                );

            Ok(
                HandshakeStatus::PairingRequired(
                    PendingPairing {
                        pairing_code,
                        result,

                        save_vita_on_success:
                            false,
                    }
                )
            )
        }

        /*
         * =================================================
         * PRIMER PAIRING MUTUO
         * =================================================
         */

        (
            false,
            0,
        ) => {
            println!(
                "Vita trust: PAIRING REQUIRED"
            );

            println!(
                "Mutual trust: new Vita identity"
            );

            let pairing_code =
                make_pairing_code(
                    &result
                        .keys
                        .session_key,

                    &result
                        .transcript_hash,
                );

            Ok(
                HandshakeStatus::PairingRequired(
                    PendingPairing {
                        pairing_code,
                        result,

                        save_vita_on_success:
                            true,
                    }
                )
            )
        }

        /*
         * =================================================
         * TRUST ASIMETRICO
         *
         * Vita reconoce al PC,
         * pero PC NO reconoce a Vita.
         *
         * NO hacemos TOFU silencioso.
         * =================================================
         */

        (
            false,
            1,
        ) => {
            bail!(
                "Mutual trust mismatch: Vita trusts this PC, but this PC does not trust the presented Vita identity. A new SAS pairing is required."
            );
        }

        (
            _,
            other,
        ) => {
            bail!(
                "Invalid Vita trust status: 0x{other:02X}"
            );
        }
    }
}

pub async fn finish_pairing(
    stream: &mut TcpStream,
    pending: PendingPairing,
    accepted: bool,
) -> Result<HandshakeResult> {
    /*
     * 1 = aceptar
     * 0 = rechazar
     */

    let pc_accept =
        if accepted {
            1u8
        } else {
            0u8
        };

    stream
        .write_all(
            &[pc_accept]
        )
        .await
        .context(
            "Could not send pairing decision to Vita"
        )?;

    /*
     * Resultado final de Vita.
     */

    let mut final_result =
        [0u8; 1];

    stream
        .read_exact(
            &mut final_result
        )
        .await
        .context(
            "Could not receive final pairing result from Vita"
        )?;

    if !accepted {
        bail!(
            "Pairing rejected by user"
        );
    }

    if final_result[0]
        != 1
    {
        bail!(
            "PAIRING REJECTED by Vita"
        );
    }

    /*
     * =====================================================
     * AHORA SI:
     *
     * La Vita ha aceptado.
     * El PC ha aceptado.
     * El SAS ha sido comprobado.
     *
     * Podemos persistir la identidad Vita.
     * =====================================================
     */

    if pending
        .save_vita_on_success
    {
        let added =
            trust_store::add_trusted(
                &pending
                    .result
                    .vita_identity_public
            )?;

        if added {
            println!(
                "Vita identity saved to PC trust store."
            );
        }
    }

    println!(
        "PAIRING SUCCESS"
    );

    receive_session_ready(
        stream
    )
    .await?;

    Ok(
        pending.result
    )
}