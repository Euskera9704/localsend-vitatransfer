use std::io::{
    self,
    Write,
};

use std::path::PathBuf;

use anyhow::Context;

use localsend::vitatransfer::{
    client,

    handshake::{
        self,
        HandshakeStatus,
    },

    identity,
    receive,
    transfer,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vita_ip =
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| {
                "192.168.1.134"
                    .to_string()
            });

    /*
     * =====================================================
     * IDENTIDAD PC
     * =====================================================
     */

    println!(
        "Loading VitaTransfer identity..."
    );

    let signing_key =
        identity
            ::load_existing_identity()?;

    /*
     * =====================================================
     * TCP
     * =====================================================
     */

    println!(
        "Connecting to VitaTransfer at {}:5000...",
        vita_ip
    );

    let mut stream =
        client::connect(
            &vita_ip
        )
        .await?;

    println!(
        "TCP connection established."
    );

    /*
     * =====================================================
     * HANDSHAKE
     * =====================================================
     */

    println!(
        "Starting VitaTransfer handshake..."
    );

    println!();

    let status =
        handshake::perform_handshake(
            &mut stream,
            &signing_key,
        )
        .await?;

    let result =
        match status {
            HandshakeStatus::Established(
                result
            ) => {
                result
            }

            HandshakeStatus::PairingRequired(
                pending
            ) => {
                println!();
                println!(
                    "========================================"
                );
                println!(
                    "NEW DEVICE - PAIRING REQUIRED"
                );
                println!();
                println!(
                    "PAIRING CODE:"
                );
                println!();
                println!(
                    "              {}",
                    pending.pairing_code
                );
                println!();
                println!(
                    "Comprueba que aparece el mismo codigo en la Vita."
                );
                println!(
                    "========================================"
                );
                println!();

                print!(
                    "¿Coincide el codigo? [s/n]: "
                );

                io::stdout()
                    .flush()?;

                let mut answer =
                    String::new();

                io::stdin()
                    .read_line(
                        &mut answer
                    )?;

                let answer =
                    answer
                        .trim()
                        .to_lowercase();

                let accepted =
                    matches!(
                        answer.as_str(),
                        "s"
                            | "si"
                            | "sí"
                            | "y"
                            | "yes"
                    );

                handshake::finish_pairing(
                    &mut stream,
                    pending,
                    accepted,
                )
                .await?
            }
        };

    println!();
    println!(
        "VITATRANSFER HANDSHAKE COMPLETE"
    );

    println!(
        "Vita identity: {}",
        identity::fingerprint(
            &result
                .vita_identity_public
        )
    );

    /*
     * =====================================================
     * DIRECTORIO DE RECEPCION
     * =====================================================
     *
     * El Python antiguo usaba:
     *
     * ~/VitaSend Received
     *
     * Como el proyecto ya se llama
     * VitaTransfer, aquí usamos el nombre
     * definitivo.
     */

    let user_profile =
        std::env::var(
            "USERPROFILE"
        )
        .context(
            "USERPROFILE environment variable is missing"
        )?;

    let output_directory =
        PathBuf::from(
            user_profile
        )
        .join(
            "VitaTransfer Received"
        );

    println!();
    println!(
        "Los archivos se guardaran en:"
    );

    println!(
        "{}",
        output_directory.display()
    );

    /*
     * =====================================================
     * PEDIR LOTE A VITA
     * =====================================================
     */

    let stats =
        receive::receive_batch(
            &mut stream,

            &result
                .keys
                .session_key,

            &result
                .keys
                .responder_to_initiator_key,

            &output_directory,
        )
        .await?;

    if stats.cancelled {
        println!(
            "No se recibieron archivos."
        );
    } else {
        println!();
        println!(
            "Recepcion completada correctamente."
        );
    }

    /*
     * =====================================================
     * CIERRE NORMAL DE SESION
     * =====================================================
     */

    transfer::close_session(
        &mut stream
    )
    .await?;

    Ok(())
}