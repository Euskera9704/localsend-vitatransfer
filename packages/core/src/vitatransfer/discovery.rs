use std::{
    io,
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    },
};

use sha2::{
    Digest,
    Sha256,
};

use tokio::net::UdpSocket;


pub const DISCOVERY_PORT: u16 = 5001;

pub const DISCOVERY_MULTICAST_ADDRESS: Ipv4Addr =
    Ipv4Addr::new(
        239,
        255,
        42,
        99,
    );

pub const DISCOVERY_MAGIC: &[u8; 8] =
    b"VTFDISC1";

pub const DISCOVERY_VERSION: u8 =
    0x01;

pub const CAPABILITY_RECEIVE: u8 =
    0x01;

pub const CAPABILITY_SEND: u8 =
    0x02;


#[derive(Debug, Clone)]
pub struct DiscoveredVita {
    pub ip: Ipv4Addr,

    pub tcp_port: u16,

    pub name: String,

    pub capabilities: u8,

    pub identity_public: [u8; 32],

    pub fingerprint: String,
}


pub async fn bind_listener() -> io::Result<UdpSocket> {
    let socket =
        UdpSocket::bind(
            (
                Ipv4Addr::UNSPECIFIED,
                DISCOVERY_PORT,
            )
        )
        .await?;


    socket.join_multicast_v4(
        DISCOVERY_MULTICAST_ADDRESS,
        Ipv4Addr::UNSPECIFIED,
    )?;


    Ok(socket)
}


pub fn parse_announcement(
    data: &[u8],
    source: SocketAddr,
) -> io::Result<DiscoveredVita> {
    /*
     * Formato:
     *
     * 8 bytes  magic
     * 1 byte   version
     * 1 byte   capabilities
     * 2 bytes  TCP port BE
     * 32 bytes Ed25519 public key
     * 1 byte   name length
     * N bytes  UTF-8 name
     */

    const FIXED_SIZE: usize =
        8 + 1 + 1 + 2 + 32 + 1;


    if data.len() < FIXED_SIZE {
        return Err(
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VitaTransfer discovery packet is too short",
            )
        );
    }


    if &data[0..8] != DISCOVERY_MAGIC {
        return Err(
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid VitaTransfer discovery magic",
            )
        );
    }


    let version =
        data[8];


    if version != DISCOVERY_VERSION {
        return Err(
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Unsupported VitaTransfer discovery version: {}",
                    version
                ),
            )
        );
    }


    let capabilities =
        data[9];


    let tcp_port =
        u16::from_be_bytes(
            [
                data[10],
                data[11],
            ]
        );


    let mut identity_public =
        [0u8; 32];


    identity_public.copy_from_slice(
        &data[12..44]
    );


    let name_length =
        data[44] as usize;


    if data.len() < FIXED_SIZE + name_length {
        return Err(
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid VitaTransfer discovery name length",
            )
        );
    }


    let name =
        std::str::from_utf8(
            &data[
                FIXED_SIZE
                    ..
                FIXED_SIZE + name_length
            ]
        )
        .map_err(
            |error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    error,
                )
            }
        )?
        .to_string();


    let ip =
        match source.ip() {
            IpAddr::V4(ip) => ip,

            IpAddr::V6(_) => {
                return Err(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unexpected IPv6 VitaTransfer discovery packet",
                    )
                );
            }
        };


    let fingerprint =
        fingerprint(
            &identity_public
        );


    Ok(
        DiscoveredVita {
            ip,
            tcp_port,
            name,
            capabilities,
            identity_public,
            fingerprint,
        }
    )
}


pub fn can_receive(
    capabilities: u8,
) -> bool {
    capabilities &
        CAPABILITY_RECEIVE
        !=
        0
}


pub fn can_send(
    capabilities: u8,
) -> bool {
    capabilities &
        CAPABILITY_SEND
        !=
        0
}


fn fingerprint(
    public_key: &[u8; 32],
) -> String {
    let digest =
        Sha256::digest(
            public_key
        );


    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        digest[4],
        digest[5],
        digest[6],
        digest[7],
    )
}