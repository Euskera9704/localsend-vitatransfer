use localsend::vitatransfer::{
    client,
    handshake,
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

    let result =
        handshake::perform_handshake(
            &mut stream,
            &signing_key,
        )
        .await?;

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