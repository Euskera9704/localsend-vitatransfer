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
    /*
     * =====================================================
     * ARGUMENTOS
     *
     * 1 = IP Vita
     * 2 = archivo PC -> Vita
     * =====================================================
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

    let send_file =
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
                    "cargo run --example vitatransfer_bidirectional --features vitatransfer -- <IP_VITA> <ARCHIVO_PC_A_VITA>"
                );

                return Ok(());
            }
        };

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
     * UN SOLO HANDSHAKE
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
        "========================================"
    );

    println!(
        "VITATRANSFER SESSION ESTABLISHED"
    );

    println!(
        "========================================"
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
     * I2R NONCE STATE
     *
     * Solo para PC -> Vita.
     *
     * Se crea UNA vez para toda esta sesión.
     * =====================================================
     */

    let mut send_state =
        transfer::SendState::new()?;

    /*
     * =====================================================
     * FASE 1
     *
     * PC -> VITA
     * =====================================================
     */

    println!();

    println!(
        "########################################"
    );

    println!(
        "FASE 1: PC -> VITA"
    );

    println!(
        "########################################"
    );

    let sent_stats =
        transfer::send_file(
            &mut stream,

            &result
                .keys
                .session_key,

            &result
                .keys
                .initiator_to_responder_key,

            &mut send_state,

            &send_file,
        )
        .await?;

    println!();

    println!(
        "FASE 1 COMPLETADA"
    );

    println!(
        "PC -> Vita: {:.2} MB transferidos",
        sent_stats.bytes_sent as f64
            / (1024.0 * 1024.0)
    );

    /*
     * IMPORTANTE:
     *
     * NO cerramos socket.
     * NO repetimos handshake.
     * NO derivamos nuevas claves.
     *
     * Seguimos usando exactamente
     * la misma sesión.
     */

    println!();

    println!(
        "La conexion sigue abierta."
    );

    println!(
        "Cambiando direccion dentro de la misma sesion..."
    );

    /*
     * =====================================================
     * DIRECTORIO DE RECEPCION
     * =====================================================
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

    /*
     * =====================================================
     * FASE 2
     *
     * VITA -> PC
     * =====================================================
     */

    println!();

    println!(
        "########################################"
    );

    println!(
        "FASE 2: VITA -> PC"
    );

    println!(
        "########################################"
    );

    println!(
        "Destino:"
    );

    println!(
        "{}",
        output_directory.display()
    );

    let received_stats =
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

    if received_stats.cancelled {
        println!();

        println!(
            "La seleccion Vita -> PC fue cancelada."
        );
    } else {
        println!();

        println!(
            "FASE 2 COMPLETADA"
        );

        println!(
            "Vita -> PC: {} archivo(s)",
            received_stats.files_received
        );

        println!(
            "Vita -> PC: {:.2} MB transferidos",
            received_stats.bytes_received as f64
                / (1024.0 * 1024.0)
        );
    }

    /*
     * =====================================================
     * TODO HA OCURRIDO BAJO:
     *
     * - mismo TCP
     * - mismo handshake
     * - mismo session_key
     *
     * pero:
     *
     * PC -> Vita = I2R key
     * Vita -> PC = R2I key
     * =====================================================
     */

    println!();

    println!(
        "========================================"
    );

    println!(
        "BIDIRECTIONAL SESSION SUCCESS"
    );

    println!(
        "========================================"
    );

    println!(
        "Misma conexion TCP: OK"
    );

    println!(
        "Un solo handshake: OK"
    );

    println!(
        "PC -> Vita: OK"
    );

    if received_stats.cancelled {
        println!(
            "Vita -> PC: CANCELLED"
        );
    } else {
        println!(
            "Vita -> PC: OK"
        );
    }

    /*
     * =====================================================
     * SESSION_END SOLO AHORA
     * =====================================================
     */

    transfer::close_session(
        &mut stream
    )
    .await?;

    Ok(())
}