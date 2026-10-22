use std::io::{
    self,
    Write,
};

use std::path::PathBuf;

use localsend::vitatransfer::{
    client,

    handshake::{
        self,
        HandshakeStatus,
    },

    identity,
    transfer,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    /*
     * Argumento 1:
     * IP Vita
     *
     * Argumento 2:
     * archivo
     */

    let mut args =
        std::env::args()
            .skip(1);

    let vita_ip =
        args.next()
            .unwrap_or_else(|| {
                "192.168.1.134"
                    .to_string()
            });

    let file_path =
        match args.next() {
            Some(path) => {
                PathBuf::from(
                    path
                )
            }

            None => {
                println!(
                    "Uso:"
                );

                println!(
                    "cargo run --example vitatransfer_connect --features vitatransfer -- <IP_VITA> <ARCHIVO>"
                );

                return Ok(());
            }
        };

    /*
     * =====================================================
     * IDENTIDAD
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
     * ESTADO DE NONCES PARA TODA LA SESION
     * =====================================================
     */

    let mut send_state =
        transfer::SendState::new()?;

    /*
     * =====================================================
     * PRIMER ARCHIVO REAL
     * =====================================================
     */

    transfer::send_file(
        &mut stream,

        &result
            .keys
            .session_key,

        &result
            .keys
            .initiator_to_responder_key,

        &mut send_state,

        &file_path,
    )
    .await?;

    /*
     * =====================================================
     * CIERRE NORMAL
     * =====================================================
     */

    transfer::close_session(
        &mut stream
    )
    .await?;

    Ok(())
}