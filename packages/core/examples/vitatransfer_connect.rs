use std::io::{
    self,
    Write,
};

use localsend::vitatransfer::{
    client,
    handshake::{
        self,
        HandshakeStatus,
    },
    identity,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vita_ip =
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| {
                "192.168.1.134".to_string()
            });

    println!(
        "Loading VitaTransfer identity..."
    );

    let signing_key =
        identity::load_existing_identity()?;

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

                io::stdout().flush()?;

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
        "VITATRANSFER HANDSHAKE COMPLETE"
    );

    println!(
        "========================================"
    );

    println!(
        "Vita identity: {}",
        identity::fingerprint(
            &result.vita_identity_public
        )
    );

    println!(
        "Authenticated encrypted session established."
    );

    println!(
        "Session key and directional keys derived successfully."
    );

    println!(
        "No files will be transferred in this test."
    );

    Ok(())
}