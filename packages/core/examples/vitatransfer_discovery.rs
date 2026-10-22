use localsend::vitatransfer::discovery;


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!(
        "VitaTransfer Discovery Test"
    );

    println!(
        "Listening on UDP multicast 239.255.42.99:5001..."
    );

    println!(
        "Open VitaTransfer Discovery Test on the PS Vita."
    );

    println!();


    let socket =
        discovery::bind_listener()
            .await?;


    let mut buffer =
        [0u8; 512];


    loop {
        let (
            length,
            source,
        ) =
            socket
                .recv_from(
                    &mut buffer
                )
                .await?;


        let device =
            match discovery::parse_announcement(
                &buffer[..length],
                source,
            ) {
                Ok(device) => device,

                Err(_) => {
                    /*
                     * Ignoramos otros paquetes multicast
                     * que no pertenezcan a VitaTransfer.
                     */
                    continue;
                }
            };


        println!(
            "========================================"
        );

        println!(
            "VITATRANSFER DEVICE DISCOVERED"
        );

        println!(
            "========================================"
        );

        println!(
            "Name:         {}",
            device.name
        );

        println!(
            "IP:           {}",
            device.ip
        );

        println!(
            "TCP port:     {}",
            device.tcp_port
        );

        println!(
            "Identity:     {}",
            device.fingerprint
        );

        println!(
            "Can send:     {}",
            if discovery::can_send(
                device.capabilities
            ) {
                "YES"
            } else {
                "NO"
            }
        );

        println!(
            "Can receive:  {}",
            if discovery::can_receive(
                device.capabilities
            ) {
                "YES"
            } else {
                "NO"
            }
        );

        println!();
    }
}