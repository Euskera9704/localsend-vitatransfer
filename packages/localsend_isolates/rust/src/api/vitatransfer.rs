use crate::frb_generated::StreamSink;

use localsend::vitatransfer::discovery;

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