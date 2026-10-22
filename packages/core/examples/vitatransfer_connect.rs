use localsend::vitatransfer::{
    client,
    handshake,
    identity,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vita_ip = std::env::args()
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
        client::connect(&vita_ip).await?;

    println!(
        "TCP connection established."
    );

    println!(
        "Exchanging identities and X25519 public keys..."
    );

    let _hello =
        handshake::exchange_hello(
            &mut stream,
            &signing_key,
        )
        .await?;

    println!();

    println!(
        "VitaTransfer hello exchange successful."
    );

    println!(
        "Stopping intentionally before Ed25519 signature."
    );

    Ok(())
}