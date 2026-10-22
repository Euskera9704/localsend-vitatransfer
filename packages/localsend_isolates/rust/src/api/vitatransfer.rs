use std::path::PathBuf;

use crate::frb_generated::StreamSink;

use localsend::vitatransfer::{
    client,
    discovery,
    handshake::{
        self,
        HandshakeStatus,
    },
    identity,
    transfer,
};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use tokio_util::sync::CancellationToken;


/*
 * =========================================================
 * DISPOSITIVO VITATRANSFER EXPUESTO A DART
 * =========================================================
 */

pub struct RsVitaTransferDevice {
    /*
     * Nombre anunciado por la Vita.
     *
     * Actualmente:
     *
     * "PS Vita"
     */
    pub name: String,

    /*
     * Dirección IP desde la que llegó
     * el anuncio UDP.
     */
    pub host: String,

    /*
     * Puerto TCP de VitaTransfer.
     *
     * Actualmente:
     *
     * 5000
     */
    pub tcp_port: u16,

    /*
     * Fingerprint de la identidad Ed25519
     * anunciada.
     *
     * IMPORTANTE:
     *
     * Sigue siendo solamente una pista de
     * discovery.
     *
     * La identidad real se verificará después
     * durante el handshake firmado.
     */
    pub fingerprint: String,

    /*
     * Clave pública incluida en el anuncio.
     *
     * También es solamente un identity hint
     * hasta completar el handshake.
     */
    pub identity_public: Vec<u8>,

    /*
     * Capacidades anunciadas por la Vita.
     */
    pub can_send: bool,
    pub can_receive: bool,
}


/*
 * =========================================================
 * DISCOVERY VITATRANSFER
 * =========================================================
 *
 * El objeto mantiene:
 *
 * - socket UDP multicast
 * - token de cancelación
 *
 * De esta forma Dart podrá:
 *
 * startVitaTransferDiscovery()
 *          |
 *          +--> listen()
 *          |
 *          +--> stop()
 */

pub struct RsVitaTransferDiscovery {
    socket: Mutex<Option<UdpSocket>>,

    cancel: CancellationToken,
}


/*
 * =========================================================
 * START
 * =========================================================
 */

pub async fn start_vitatransfer_discovery(
) -> anyhow::Result<RsVitaTransferDiscovery> {
    let socket =
        discovery::bind_listener()
            .await?;


    Ok(
        RsVitaTransferDiscovery {
            socket:
                Mutex::new(
                    Some(socket)
                ),

            cancel:
                CancellationToken::new(),
        }
    )
}


/*
 * =========================================================
 * LISTEN / STOP
 * =========================================================
 */

impl RsVitaTransferDiscovery {
    /*
     * Stream hacia Dart.
     *
     * Cada anuncio válido de VitaTransfer genera
     * un RsVitaTransferDevice.
     */

    pub async fn listen(
        &self,

        sink: StreamSink<RsVitaTransferDevice>,
    ) {
        /*
         * El socket solo puede ser escuchado
         * una vez.
         */

        let socket =
            {
                let mut guard =
                    self.socket
                        .lock()
                        .await;


                match guard.take() {
                    Some(socket) => socket,

                    None => {
                        let _ =
                            sink.add_error(
                                anyhow::anyhow!(
                                    "VitaTransfer discovery is already being listened to"
                                )
                            );

                        return;
                    }
                }
            };


        let mut buffer =
            [0u8; 512];


        loop {
            tokio::select! {
                /*
                 * =================================================
                 * ANUNCIO UDP
                 * =================================================
                 */

                result =
                    socket.recv_from(
                        &mut buffer
                    )
                => {
                    let (
                        length,
                        source,
                    ) =
                        match result {
                            Ok(result) => result,

                            Err(error) => {
                                let _ =
                                    sink.add_error(
                                        anyhow::anyhow!(
                                            "VitaTransfer discovery receive failed: {error}"
                                        )
                                    );

                                break;
                            }
                        };


                    /*
                     * Ignoramos silenciosamente cualquier paquete
                     * multicast que no sea VitaTransfer.
                     */

                    let device =
                        match discovery::parse_announcement(
                            &buffer[..length],
                            source,
                        ) {
                            Ok(device) => device,

                            Err(_) => {
                                continue;
                            }
                        };


                    let event =
                        RsVitaTransferDevice {
                            name:
                                device.name,

                            host:
                                device.ip
                                    .to_string(),

                            tcp_port:
                                device.tcp_port,

                            fingerprint:
                                device.fingerprint,

                            identity_public:
                                device.identity_public
                                    .to_vec(),

                            can_send:
                                discovery::can_send(
                                    device.capabilities
                                ),

                            can_receive:
                                discovery::can_receive(
                                    device.capabilities
                                ),
                        };


                    /*
                     * Si Dart ya no escucha el stream,
                     * terminamos la tarea y soltamos
                     * el socket UDP.
                     */

                    if sink.add(event).is_err() {
                        break;
                    }
                }


                /*
                 * =================================================
                 * STOP
                 * =================================================
                 */

                _ =
                    self.cancel.cancelled()
                => {
                    break;
                }
            }
        }
    }


    /*
     * Detiene el listener.
     *
     * El select! de listen() despertará aunque
     * recv_from() esté esperando un paquete.
     */

    pub fn stop(
        &self
    ) {
        self.cancel
            .cancel();
    }
}

/* ========================================================= */
/* ENVIO PC -> VITA DESDE FLUTTER                            */
/* ========================================================= */

pub enum RsVitaTransferSendStatus {
    Completed,
    PairingRequired,
}


pub struct RsVitaTransferSendResult {
    pub status: RsVitaTransferSendStatus,

    /*
     * Solo tendrá valor si la Vita todavía
     * necesita pairing SAS.
     *
     * En esta primera prueba nuestra Vita
     * ya está emparejada, así que será null.
     */
    pub pairing_code: Option<String>,

    pub files_sent: u32,

    pub bytes_sent: u64,
}


/*
 * Primera API de envío usable desde Dart.
 *
 * Por ahora:
 *
 * - recibe únicamente rutas reales de archivos;
 * - usa una única conexión;
 * - usa un único handshake;
 * - reutiliza SendState durante todos los archivos;
 * - cierra la sesión limpiamente al terminar.
 *
 * El diálogo SAS y los eventos de progreso se
 * añadirán después de validar este camino.
 */
pub async fn send_vitatransfer_files(
    host: String,
    paths: Vec<String>,
) -> anyhow::Result<RsVitaTransferSendResult> {
    if paths.is_empty() {
        anyhow::bail!(
            "No files were provided to VitaTransfer"
        );
    }


    /*
     * =====================================================
     * IDENTIDAD PC
     * =====================================================
     */

    let signing_key =
        identity::load_existing_identity()?;


    /*
     * =====================================================
     * TCP
     * =====================================================
     */

    let mut stream =
        client::connect(
            &host
        )
        .await?;


    /*
     * =====================================================
     * HANDSHAKE
     * =====================================================
     */

    let handshake_status =
        handshake::perform_handshake(
            &mut stream,
            &signing_key,
        )
        .await?;


    let handshake_result =
        match handshake_status {
            HandshakeStatus::Established(
                result
            ) => {
                result
            }


            HandshakeStatus::PairingRequired(
                pending
            ) => {
                /*
                 * Esta primera integración todavía no
                 * muestra el diálogo SAS en Flutter.
                 *
                 * Devolvemos el código a Dart y dejamos
                 * esa UX para la siguiente fase.
                 */

                return Ok(
                    RsVitaTransferSendResult {
                        status:
                            RsVitaTransferSendStatus::PairingRequired,

                        pairing_code:
                            Some(
                                pending.pairing_code
                            ),

                        files_sent:
                            0,

                        bytes_sent:
                            0,
                    }
                );
            }
        };


    /*
     * =====================================================
     * NONCE STATE PC -> VITA
     * =====================================================
     *
     * IMPORTANTE:
     *
     * Se crea UNA sola vez por sesión y se reutiliza
     * para todos los archivos.
     */

    let mut send_state =
        transfer::SendState::new()?;


    let mut files_sent: u32 =
        0;

    let mut bytes_sent: u64 =
        0;


    /*
     * =====================================================
     * ARCHIVOS
     * =====================================================
     */

    for path in paths {
        let path =
            PathBuf::from(
                path
            );


        let stats =
            transfer::send_file(
                &mut stream,

                &handshake_result
                    .keys
                    .session_key,

                &handshake_result
                    .keys
                    .initiator_to_responder_key,

                &mut send_state,

                &path,
            )
            .await?;


        files_sent +=
            1;

        bytes_sent +=
            stats.bytes_sent;
    }


    /*
     * =====================================================
     * CIERRE NORMAL
     * =====================================================
     */

    transfer::close_session(
        &mut stream
    )
    .await?;


    Ok(
        RsVitaTransferSendResult {
            status:
                RsVitaTransferSendStatus::Completed,

            pairing_code:
                None,

            files_sent,

            bytes_sent,
        }
    )
}