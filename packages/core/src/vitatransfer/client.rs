use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::protocol::PORT;

const CONNECT_TIMEOUT: Duration =
    Duration::from_secs(5);

pub async fn connect(
    host: &str,
) -> Result<TcpStream> {
    let address = format!("{host}:{PORT}");

    let stream = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect(&address),
    )
    .await
    .context("VitaTransfer connection timed out")?
    .with_context(|| {
        format!(
            "Could not connect to VitaTransfer at {address}"
        )
    })?;

    stream
        .set_nodelay(true)
        .context(
            "Could not enable TCP_NODELAY for VitaTransfer",
        )?;

    Ok(stream)
}