use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{
    Arc,
    Mutex as StdMutex,
    OnceLock,
    atomic::{
        AtomicU64,
        Ordering,
    },
};

use crate::frb_generated::StreamSink;

use localsend::vitatransfer::{
    client,
    discovery,
    handshake::{
        self,
        HandshakeStatus,
    },
    identity,
    receive,
    transfer,
};

use tokio::io::AsyncWriteExt;
use tokio::net::{
    TcpListener,
    TcpStream,
    UdpSocket,
};

use tokio::sync::{
    Mutex,
    mpsc,
};

use tokio_util::sync::CancellationToken;

const PC_DISCOVERY_PORT:
    u16 = 5002;

const PC_RECEIVE_PORT:
    u16 = 5002;

const PC_DISCOVERY_QUERY_MAGIC:
    &[u8] = b"VTFHOSTQ";

const PC_DISCOVERY_REPLY_MAGIC:
    &[u8] = b"VTFHOST1";

const PC_DISCOVERY_VERSION:
    u8 = 0x01;



const PC_DISCOVERY_MULTICAST:
    Ipv4Addr =
        Ipv4Addr::new(
            239,
            255,
            42,
            99,
        );


/*
 * =========================================================
 * DESTINO TEMPORAL VITA -> PC
 * =========================================================
 *
 * Para esta primera integración funcional guardamos en:
 *
 * Windows:
 *     %USERPROFILE%\Downloads\VitaTransfer
 *
 * Linux/macOS:
 *     $HOME/Downloads/VitaTransfer
 *
 * Después conectaremos esto con la carpeta configurada
 * realmente por LocalSend.
 */
fn vitatransfer_receive_directory(
) -> PathBuf {
    if let Some(profile) =
        std::env::var_os(
            "USERPROFILE"
        )
    {
        return PathBuf::from(
            profile
        )
        .join(
            "Downloads"
        )
        .join(
            "VitaTransfer"
        );
    }


    if let Some(home) =
        std::env::var_os(
            "HOME"
        )
    {
        return PathBuf::from(
            home
        )
        .join(
            "Downloads"
        )
        .join(
            "VitaTransfer"
        );
    }


    std::env::temp_dir()
        .join(
            "VitaTransfer"
        )
}

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
 * OFERTA ENTRANTE VITA -> PC
 * =========================================================
 */

pub struct RsVitaTransferIncomingFile {
    pub id: String,
    pub file_name: String,
    pub size: u64,
}


pub struct RsVitaTransferIncomingOffer {
    pub session_id: String,

    pub sender_name: String,
    pub sender_host: String,
    pub sender_fingerprint: String,

    pub files:
        Vec<RsVitaTransferIncomingFile>,
}

#[derive(Debug, Clone)]
pub struct RsVitaTransferReceiveProgress {
    pub session_id: String,

    pub file_name: String,

    pub file_number: u16,

    pub file_count: u16,

    pub file_bytes_received: u64,

    pub file_size: u64,

    /*
     * Bytes recibidos en todo el lote hasta este momento.
     *
     * Dart conoce el tamaño total del lote mediante
     * el manifest, así que podrá calcular el porcentaje
     * global.
     */
    pub batch_bytes_received: u64,

    pub megabytes_per_second: f64,

    /*
     * true únicamente cuando este archivo ya ha
     * terminado y ha superado SHA-256.
     */
    pub file_finished: bool,
}


/*
 * Estado privado.
 *
 * NO viaja a Flutter.
 *
 * Mantiene exactamente la misma conexión TCP y
 * las mismas claves derivadas durante el handshake.
 */
struct VitaTransferIncomingSessionState {
    stream:
        TcpStream,

    handshake_result:
        handshake::HandshakeResult,
}


/*
 * =========================================================
 * REGISTRO DE SESIONES ENTRANTES
 * =========================================================
 */

static NEXT_INCOMING_SESSION_ID:
    AtomicU64 =
        AtomicU64::new(1);


static INCOMING_SESSIONS:
    OnceLock<
        Mutex<
            HashMap<
                String,
                VitaTransferIncomingSessionState
            >
        >
    > =
        OnceLock::new();


/*
 * =========================================================
 * CANCELACIÓN DE TRANSFERENCIAS ENTRANTES ACTIVAS
 * =========================================================
 *
 * Una vez que Aceptar consume INCOMING_SESSIONS,
 * necesitamos conservar una forma de cancelar la
 * transferencia que ya está ejecutándose.
 */

static ACTIVE_INCOMING_CANCELS:
    OnceLock<
        Mutex<
            HashMap<
                String,
                CancellationToken
            >
        >
    > =
        OnceLock::new();


fn active_incoming_cancels(
) -> &'static Mutex<
    HashMap<
        String,
        CancellationToken
    >
> {
    ACTIVE_INCOMING_CANCELS
        .get_or_init(
            || {
                Mutex::new(
                    HashMap::new()
                )
            }
        )
}


fn incoming_sessions(
) -> &'static Mutex<
    HashMap<
        String,
        VitaTransferIncomingSessionState
    >
> {
    INCOMING_SESSIONS
        .get_or_init(
            || {
                Mutex::new(
                    HashMap::new()
                )
            }
        )
}


fn vita_identity_fingerprint(
    identity: &[u8; 32],
) -> String {
    identity
        .iter()
        .take(8)
        .map(
            |byte| {
                format!(
                    "{byte:02X}"
                )
            }
        )
        .collect::<Vec<_>>()
        .join(":")
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
    /*
     * Listener de anuncios PS Vita:
     *
     * 239.255.42.99:5001
     */
    socket:
        Mutex<Option<UdpSocket>>,

    /*
     * Listener de consultas iniciadas por Vita:
     *
     * 239.255.42.99:5002
     */
    pc_discovery_socket:
        Mutex<Option<UdpSocket>>,

    /*
    * Listener TCP para conexiones iniciadas
    * por la PS Vita.
    *
    * TCP 5002.
    */
    pc_receive_listener:
        Mutex<Option<TcpListener>>,

    /*
     * Respuesta ya construida.
     */
    pc_discovery_reply:
        Vec<u8>,

    /*
    * Ofertas Vita -> PC listas para ser
    * entregadas a Flutter.
    */
    incoming_offer_tx:
        mpsc::UnboundedSender<
            RsVitaTransferIncomingOffer
        >,

    incoming_offer_rx:
        Mutex<
            Option<
                mpsc::UnboundedReceiver<
                    RsVitaTransferIncomingOffer
                >
            >
        >,

    cancel:
        CancellationToken,
}


/*
 * =========================================================
 * START
 * =========================================================
 */

pub async fn start_vitatransfer_discovery(
    pc_name: String,
) -> anyhow::Result<RsVitaTransferDiscovery> {
    /*
     * =====================================================
     * DISCOVERY VITA -> PC YA EXISTENTE
     * =====================================================
     */

    let socket =
        discovery::bind_listener()
            .await?;


    /*
     * =====================================================
     * DISCOVERY INVERSO: VITA BUSCA PC
     * =====================================================
     */

    let pc_discovery_socket =
        UdpSocket::bind(
            (
                Ipv4Addr::UNSPECIFIED,
                PC_DISCOVERY_PORT,
            )
        )
        .await?;


    pc_discovery_socket
        .join_multicast_v4(
            PC_DISCOVERY_MULTICAST,
            Ipv4Addr::UNSPECIFIED,
        )?;

    /*
    * =====================================================
    * LISTENER TCP VITA -> PC
    * =====================================================
    *
    * La Vita será quien haga connect().
    */

    let pc_receive_listener =
        TcpListener::bind(
            (
                Ipv4Addr::UNSPECIFIED,
                PC_RECEIVE_PORT,
            )
        )
        .await?;

    /*
     * =====================================================
     * IDENTIDAD PC
     * =====================================================
     *
     * Es solamente identity hint en discovery.
     *
     * La autenticación real seguirá siendo el handshake
     * firmado Ed25519/X25519.
     */

    let signing_key =
        identity::load_existing_identity()?;


    let identity_public =
        signing_key
            .verifying_key()
            .to_bytes();


    /*
     * =====================================================
     * CONSTRUIR RESPUESTA
     * =====================================================
     *
     * 8 bytes  magic "VTFHOST1"
     * 1 byte   version
     * 2 bytes  TCP port big endian
     * 32 bytes Ed25519 public key
     * 1 byte   name length
     * N bytes  name
     */

    /*
    * =====================================================
    * NOMBRE REAL DE LOCALSEND
    * =====================================================
    *
    * Recibimos el alias configurado por el usuario
    * en LocalSend.
    *
    * La Vita admite como máximo 63 bytes para este
    * campo de discovery.
    */

    let pc_name =
        pc_name
            .trim();


    let pc_name =
        if pc_name.is_empty() {
            "LocalSend PC"
        } else {
            pc_name
        };


    let mut name_end =
        pc_name
            .len()
            .min(63);


    while name_end > 0 && !pc_name.is_char_boundary(name_end) {
        name_end -=
            1;
    }


    let name =
        pc_name[..name_end]
            .as_bytes();


    let mut pc_discovery_reply =
        Vec::with_capacity(
            8 +
            1 +
            2 +
            identity_public.len() +
            1 +
            name.len()
        );


    pc_discovery_reply
        .extend_from_slice(
            PC_DISCOVERY_REPLY_MAGIC
        );


    pc_discovery_reply
        .push(
            PC_DISCOVERY_VERSION
        );


    pc_discovery_reply
        .extend_from_slice(
            &PC_RECEIVE_PORT
                .to_be_bytes()
        );


    pc_discovery_reply
        .extend_from_slice(
            &identity_public
        );


    pc_discovery_reply
        .push(
            name.len() as u8
        );


    pc_discovery_reply
        .extend_from_slice(
            name
        );

    let (
        incoming_offer_tx,
        incoming_offer_rx,
    ) =
        mpsc::unbounded_channel();

    Ok(
        RsVitaTransferDiscovery {
            socket:
                Mutex::new(
                    Some(socket)
                ),

            pc_discovery_socket:
                Mutex::new(
                    Some(
                        pc_discovery_socket
                    )
                ),

            pc_receive_listener:
                Mutex::new(
                    Some(
                        pc_receive_listener
                    )
                ),

            pc_discovery_reply,

            incoming_offer_tx,

            incoming_offer_rx:
                Mutex::new(
                    Some(
                        incoming_offer_rx
                    )
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


        let pc_discovery_socket =
            {
                let mut guard =
                    self
                        .pc_discovery_socket
                        .lock()
                        .await;


                match guard.take() {
                    Some(socket) => {
                        socket
                    }


                    None => {
                        let _ =
                            sink.add_error(
                                anyhow::anyhow!(
                                    "VitaTransfer PC discovery responder is already being listened to"
                                )
                            );


                        return;
                    }
                }
            };


        let pc_receive_listener =
        {
            let mut guard =
                self
                    .pc_receive_listener
                    .lock()
                    .await;


            match guard.take() {
                Some(listener) => {
                    listener
                }


                None => {
                    let _ =
                        sink.add_error(
                            anyhow::anyhow!(
                                "VitaTransfer PC receive listener is already being listened to"
                            )
                        );


                    return;
                }
            }
        };

        let mut buffer =
            [0u8; 512];

        let mut pc_discovery_buffer =
            [0u8; 128];

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
                * VITA PREGUNTA POR PCs DISPONIBLES
                * =================================================
                */

                result =
                    pc_discovery_socket
                        .recv_from(
                            &mut pc_discovery_buffer
                        )
                => {
                    let (
                        length,
                        source,
                    ) =
                        match result {
                            Ok(result) => {
                                result
                            }


                            Err(error) => {
                                let _ =
                                    sink.add_error(
                                        anyhow::anyhow!(
                                            "VitaTransfer PC discovery receive failed: {error}"
                                        )
                                    );


                                break;
                            }
                        };


                    /*
                    * Solo respondemos a:
                    *
                    *     VTFHOSTQ
                    */

                    if length ==
                        PC_DISCOVERY_QUERY_MAGIC.len()
                        &&
                        &pc_discovery_buffer[..length] ==
                        PC_DISCOVERY_QUERY_MAGIC
                    {
                        println!(
                            "[VitaTransfer] PS Vita requested PC discovery from {source}"
                        );


                        if let Err(error) =
                            pc_discovery_socket
                                .send_to(
                                    &self.pc_discovery_reply,
                                    source,
                                )
                                .await
                        {
                            eprintln!(
                                "[VitaTransfer] Could not send PC discovery reply: {error}"
                            );
                        }
                    }
                }


                /*
                * =================================================
                * CONEXION TCP INICIADA POR VITA
                * =================================================
                */

                result =
                    pc_receive_listener
                        .accept()
                => {
                    match result {
                        Ok((
                            mut stream,
                            source,
                        )) => {
                            println!(
                                "[VitaTransfer] Incoming Vita TCP connection from {source}"
                            );


                            /*
                            * =================================================
                            * HANDSHAKE SEGURO
                            * =================================================
                            *
                            * Aunque la Vita haya iniciado TCP,
                            * el PC sigue siendo el iniciador criptográfico.
                            */

                            let signing_key =
                                match identity::load_existing_identity() {
                                    Ok(key) => {
                                        key
                                    }


                                    Err(error) => {
                                        eprintln!(
                                            "[VitaTransfer] Could not load PC identity: {error}"
                                        );

                                        continue;
                                    }
                                };


                            let handshake_status =
                                match handshake::perform_handshake(
                                    &mut stream,
                                    &signing_key,
                                )
                                .await
                                {
                                    Ok(status) => {
                                        status
                                    }


                                    Err(error) => {
                                        eprintln!(
                                            "[VitaTransfer] Incoming Vita handshake failed: {error}"
                                        );

                                        continue;
                                    }
                                };


                            match handshake_status {
                                HandshakeStatus::Established(
                                    result
                                ) => {
                                    println!(
                                        "[VitaTransfer] Incoming Vita secure handshake established"
                                    );


                                    /*
                                    * =================================================
                                    * DESTINO
                                    * =================================================
                                    */

                                    let output_directory =
                                        vitatransfer_receive_directory();


                                    println!(
                                        "[VitaTransfer] Vita receive directory: {}",
                                        output_directory.display()
                                    );

                                    let manifest =
                                        match receive::receive_batch_manifest(
                                            &mut stream,

                                            &result
                                                .keys
                                                .session_key,
                                        )
                                        .await
                                        {
                                            Ok(manifest) => {
                                                manifest
                                            }

                                            Err(error) => {
                                                eprintln!(
                                                    "[VitaTransfer] Could not receive Vita manifest: {error}"
                                                );

                                                continue;
                                            }
                                        };


                                    println!(
                                        "[VitaTransfer] Incoming Vita offer: {} file(s)",
                                        manifest.files.len()
                                    );


                                    for file in &manifest.files {
                                        println!(
                                            "[VitaTransfer]   {} ({:.2} MB)",
                                            file.filename,
                                            file.size as f64 /
                                                (1024.0 * 1024.0),
                                        );
                                    }

                                    println!(
                                        "[VitaTransfer] Manifest received successfully; waiting for UI integration"
                                    );

                                    /*
                                    * =========================================================
                                    * CREAR SESION ENTRANTE PERSISTENTE
                                    * =========================================================
                                    */

                                    let session_number =
                                        NEXT_INCOMING_SESSION_ID
                                            .fetch_add(
                                                1,
                                                Ordering::Relaxed,
                                            );


                                    let session_id =
                                        format!(
                                            "vita-{session_number}"
                                        );


                                    let sender_fingerprint =
                                        vita_identity_fingerprint(
                                            &result
                                                .vita_identity_public
                                        );


                                    let incoming_files =
                                        manifest
                                            .files
                                            .iter()
                                            .enumerate()
                                            .map(
                                                |(
                                                    index,
                                                    file,
                                                )| {
                                                    RsVitaTransferIncomingFile {
                                                        id:
                                                            format!(
                                                                "vita-file-{index}"
                                                            ),

                                                        file_name:
                                                            file
                                                                .filename
                                                                .clone(),

                                                        size:
                                                            file.size,
                                                    }
                                                }
                                            )
                                            .collect::<Vec<_>>();


                                    let offer =
                                        RsVitaTransferIncomingOffer {
                                            session_id:
                                                session_id.clone(),

                                            sender_name:
                                                "PS Vita"
                                                    .to_string(),

                                            sender_host:
                                                source
                                                    .ip()
                                                    .to_string(),

                                            sender_fingerprint,

                                            files:
                                                incoming_files,
                                        };


                                    /*
                                    * Guardamos PRIMERO la sesión.
                                    *
                                    * A partir de aquí el TcpStream ya no pertenece
                                    * a esta rama: queda retenido por el registro.
                                    */
                                    {
                                        let mut sessions =
                                            incoming_sessions()
                                                .lock()
                                                .await;


                                        sessions.insert(
                                            session_id.clone(),

                                            VitaTransferIncomingSessionState {
                                                stream,

                                                handshake_result:
                                                    result,
                                            },
                                        );
                                    }


                                    /*
                                    * Ahora avisamos a Flutter.
                                    */
                                    if self
                                        .incoming_offer_tx
                                        .send(
                                            offer
                                        )
                                        .is_err()
                                    {
                                        eprintln!(
                                            "[VitaTransfer] No Dart listener available for incoming Vita offer"
                                        );


                                        /*
                                        * Si Dart desapareció, sacamos de nuevo la
                                        * sesión para no dejar el socket colgado.
                                        */
                                        let removed =
                                            {
                                                let mut sessions =
                                                    incoming_sessions()
                                                        .lock()
                                                        .await;


                                                sessions.remove(
                                                    &session_id
                                                )
                                            };


                                        if let Some(
                                            mut incoming_session
                                        ) = removed
                                        {
                                            let _ =
                                                transfer::close_session(
                                                    &mut incoming_session
                                                        .stream
                                                )
                                                .await;
                                        }
                                    }
                                    else
                                    {
                                        println!(
                                            "[VitaTransfer] Incoming Vita session retained: {session_id}"
                                        );
                                    }


                                }


                                HandshakeStatus::PairingRequired(
                                    pending
                                ) => {
                                    println!(
                                        "[VitaTransfer] Incoming Vita pairing required. SAS: {}",
                                        pending.pairing_code
                                    );


                                    /*
                                    * El pairing entrante con UI Flutter lo
                                    * implementaremos después.
                                    *
                                    * En esta prueba esperamos que NO entre aquí,
                                    * porque PC y Vita ya son de confianza.
                                    */
                                }
                            }
                        }


                        Err(error) => {
                            eprintln!(
                                "[VitaTransfer] Vita TCP accept failed: {error}"
                            );
                        }
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
    * =========================================================
    * OFERTAS ENTRANTES VITA -> PC
    * =========================================================
    */

    pub async fn listen_incoming(
        &self,

        sink:
            StreamSink<
                RsVitaTransferIncomingOffer
            >,
    ) {
        let mut receiver =
            {
                let mut guard =
                    self
                        .incoming_offer_rx
                        .lock()
                        .await;


                match guard.take() {
                    Some(receiver) => {
                        receiver
                    }


                    None => {
                        let _ =
                            sink.add_error(
                                anyhow::anyhow!(
                                    "VitaTransfer incoming offer stream is already being listened to"
                                )
                            );


                        return;
                    }
                }
            };


        loop {
            tokio::select! {
                offer =
                    receiver.recv()
                => {
                    match offer {
                        Some(offer) => {
                            if sink
                                .add(
                                    offer
                                )
                                .is_err()
                            {
                                break;
                            }
                        }


                        None => {
                            break;
                        }
                    }
                }


                _ =
                    self.cancel
                        .cancelled()
                => {
                    break;
                }
            }
        }
    }

    /*
     * =========================================================
     * RECHAZAR OFERTA ENTRANTE VITA -> PC
     * =========================================================
     *
     * Recupera exactamente la sesión retenida después
     * de recibir el manifest.
     *
     * La sesión se elimina del registro ANTES de cerrar
     * el protocolo, de modo que no pueda reutilizarse.
     */

    pub async fn reject_incoming(
        &self,
        session_id: String,
    ) -> anyhow::Result<()> {
        let mut incoming_session =
            {
                let mut sessions =
                    incoming_sessions()
                        .lock()
                        .await;

                sessions
                    .remove(
                        &session_id
                    )
                    .ok_or_else(
                        || {
                            anyhow::anyhow!(
                                "Unknown VitaTransfer incoming session: {}",
                                session_id
                            )
                        }
                    )?
            };


        println!(
            "[VitaTransfer] Rejecting incoming Vita session: {}",
            session_id
        );


        /*
         * Por ahora el rechazo utiliza el cierre limpio
         * del protocolo ya existente:
         *
         * PC   -> COMMAND_SESSION_END
         * Vita -> SESSION_END_ACK
         */
        transfer::close_session(
            &mut incoming_session.stream
        )
        .await?;


        println!(
            "[VitaTransfer] Incoming Vita session rejected and released: {}",
            session_id
        );


        Ok(())
    }


    /*
     * =========================================================
     * ACEPTAR OFERTA ENTRANTE VITA -> PC
     * =========================================================
     *
     * Recupera exactamente la sesión retenida después
     * del manifest:
     *
     * - mismo TcpStream;
     * - mismo handshake;
     * - misma session_key;
     * - misma responder_to_initiator_key.
     *
     * No se realiza un nuevo handshake.
     */

    /*
    * =========================================================
    * CANCELAR TRANSFERENCIA ENTRANTE YA ACEPTADA
    * =========================================================
    */

    pub async fn cancel_incoming_transfer(
        &self,
        session_id: String,
    ) -> anyhow::Result<()> {
        let cancel =
            {
                let active =
                    active_incoming_cancels()
                        .lock()
                        .await;

                active
                    .get(
                        &session_id
                    )
                    .cloned()
                    .ok_or_else(
                        || {
                            anyhow::anyhow!(
                                "No active VitaTransfer incoming transfer: {}",
                                session_id
                            )
                        }
                    )?
            };


        println!(
            "[VitaTransfer] Cancelling incoming Vita transfer: {}",
            session_id
        );


        cancel.cancel();


        Ok(())
    }

    pub async fn accept_incoming(
        &self,
        session_id: String,
    ) -> anyhow::Result<()> {
        let incoming_session =
            {
                let mut sessions =
                    incoming_sessions()
                        .lock()
                        .await;

                sessions
                    .remove(
                        &session_id
                    )
                    .ok_or_else(
                        || {
                            anyhow::anyhow!(
                                "Unknown VitaTransfer incoming session: {}",
                                session_id
                            )
                        }
                    )?
            };


        /*
         * Separamos las dos partes de la sesión para poder
         * usar el stream mutable y las claves del handshake.
         */
        let VitaTransferIncomingSessionState {
            mut stream,
            handshake_result,
        } = incoming_session;


        println!(
            "[VitaTransfer] Accepting incoming Vita session: {}",
            session_id
        );


        let output_directory =
            vitatransfer_receive_directory();


        println!(
            "[VitaTransfer] Starting incoming Vita batch"
        );

        println!(
            "[VitaTransfer] Receive directory: {}",
            output_directory.display()
        );


        /*
         * receive_batch() ya implementa el receptor que
         * utilizamos en las pruebas Vita -> PC anteriores.
         *
         * El comando 0x03 hará que la Vita empiece a enviar
         * el lote que ya seleccionó antes del manifest.
         */
        let receive_result =
            receive::receive_batch(
                &mut stream,

                &handshake_result
                    .keys
                    .session_key,

                &handshake_result
                    .keys
                    .responder_to_initiator_key,

                &output_directory,
            )
            .await;


        match receive_result {
            Ok(stats) => {
                if stats.cancelled {
                    println!(
                        "[VitaTransfer] Incoming Vita batch cancelled"
                    );
                }
                else {
                    println!(
                        "[VitaTransfer] Incoming Vita batch complete: {} file(s), {:.2} MB, {:.2} MB/s",
                        stats.files_received,
                        stats.bytes_received as f64
                            / (1024.0 * 1024.0),
                        stats.megabytes_per_second,
                    );
                }


                /*
                 * Una vez terminado el lote cerramos la misma
                 * sesión de forma limpia.
                 */
                transfer::close_session(
                    &mut stream
                )
                .await?;


                println!(
                    "[VitaTransfer] Incoming Vita session completed and released: {}",
                    session_id
                );


                Ok(())
            }


            Err(error) => {
                eprintln!(
                    "[VitaTransfer] Incoming Vita transfer failed for {}: {}",
                    session_id,
                    error
                );


                /*
                 * Intentamos cerrar limpiamente incluso
                 * después de un error. Si este cierre también
                 * falla, conservamos como error principal el
                 * de la transferencia.
                 */
                let _ =
                    transfer::close_session(
                        &mut stream
                    )
                    .await;


                Err(error)
            }
        }
    }

    /*
     * =========================================================
     * ACEPTAR OFERTA VITA -> PC CON STREAM DE PROGRESO
     * =========================================================
     *
     * Es el equivalente a accept_incoming(), pero utiliza
     * receive_batch_with_progress() y publica cada actualización
     * hacia Dart mediante StreamSink.
     */

    pub async fn accept_incoming_with_progress(
        &self,
        session_id: String,
        sink: StreamSink<RsVitaTransferReceiveProgress>,
    ) -> anyhow::Result<()> {
        let incoming_session =
            {
                let mut sessions =
                    incoming_sessions()
                        .lock()
                        .await;

                sessions
                    .remove(
                        &session_id
                    )
                    .ok_or_else(
                        || {
                            anyhow::anyhow!(
                                "Unknown VitaTransfer incoming session: {}",
                                session_id
                            )
                        }
                    )?
            };


        let VitaTransferIncomingSessionState {
            mut stream,
            handshake_result,
        } = incoming_session;

        let transfer_cancel =
            CancellationToken::new();


        active_incoming_cancels()
            .lock()
            .await
            .insert(
                session_id.clone(),
                transfer_cancel.clone(),
            );


        println!(
            "[VitaTransfer] Accepting incoming Vita session with progress: {}",
            session_id
        );


        let output_directory =
            vitatransfer_receive_directory();


        println!(
            "[VitaTransfer] Starting incoming Vita batch with progress"
        );

        println!(
            "[VitaTransfer] Receive directory: {}",
            output_directory.display()
        );


        /*
         * Cantidad de bytes pertenecientes a archivos
         * ya terminados.
         *
         * Permite transformar el progreso individual
         * de receive.rs en progreso global del lote.
         */
        let mut completed_batch_bytes:
            u64 =
            0;


        let mut current_file_number:
            u16 =
            0;


        let mut current_file_base:
            u64 =
            0;

        /*
        * Nombre del archivo que está actualmente incompleto.
        *
        * None:
        * - todavía no empezó ningún archivo, o
        * - el último archivo terminó y pasó SHA-256.
        *
        * Some(nombre):
        * - ese archivo está actualmente en recepción.
        */
        let current_partial_filename =
            Arc::new(
                StdMutex::new(
                    None::<String>
                )
            );


        let progress_partial_filename =
            Arc::clone(
                &current_partial_filename
            );

        let progress_session_id =
            session_id.clone();


        let mut on_progress =
            move |
                progress:
                    receive::BatchReceiveProgress
            | {

                /*
                * Seguimos qué archivo está incompleto.
                *
                * file_finished solo llega a true después
                * de terminar y superar SHA-256.
                */
                if let Ok(
                    mut partial
                ) =
                    progress_partial_filename
                        .lock()
                {
                    if progress.file_finished {
                        *partial =
                            None;
                    } else {
                        *partial =
                            Some(
                                progress.filename.clone()
                            );
                    }
                }

                /*
                 * Al entrar en un nuevo archivo,
                 * fijamos como base todos los bytes
                 * completados anteriormente.
                 */
                if progress.file_number !=
                    current_file_number
                {
                    current_file_number =
                        progress.file_number;

                    current_file_base =
                        completed_batch_bytes;
                }


                let batch_bytes_received =
                    current_file_base
                        .saturating_add(
                            progress
                                .file_bytes_received
                        );


                let _ =
                    sink.add(
                        RsVitaTransferReceiveProgress {
                            session_id:
                                progress_session_id
                                    .clone(),

                            file_name:
                                progress.filename
                                    .clone(),

                            file_number:
                                progress.file_number,

                            file_count:
                                progress.file_count,

                            file_bytes_received:
                                progress
                                    .file_bytes_received,

                            file_size:
                                progress.file_size,

                            batch_bytes_received,

                            megabytes_per_second:
                                progress
                                    .megabytes_per_second,

                            file_finished:
                                progress.file_finished,
                        }
                    );


                /*
                 * Solo consolidamos estos bytes como
                 * terminados cuando SHA-256 ya ha sido
                 * validado.
                 */
                if progress.file_finished {
                    completed_batch_bytes =
                        batch_bytes_received;
                }
            };


        enum IncomingReceiveOutcome {
            Finished(
                anyhow::Result<
                    receive::BatchReceiveStats
                >
            ),

            Cancelled,
        }


        let outcome =
            tokio::select! {
                result =
                    receive::receive_batch_with_progress(
                        &mut stream,

                        &handshake_result
                            .keys
                            .session_key,

                        &handshake_result
                            .keys
                            .responder_to_initiator_key,

                        &output_directory,

                        &mut on_progress,
                    )
                => {
                    IncomingReceiveOutcome::Finished(
                        result
                    )
                }


                _ =
                    transfer_cancel.cancelled()
                => {
                    IncomingReceiveOutcome::Cancelled
                }
            };


        active_incoming_cancels()
            .lock()
            .await
            .remove(
                &session_id
            );


        let receive_result =
            match outcome {
                IncomingReceiveOutcome::Finished(
                    result
                ) => {
                    result
                }


                IncomingReceiveOutcome::Cancelled => {
                    println!(
                        "[VitaTransfer] Incoming Vita transfer cancelled: {}",
                        session_id
                    );


                    /*
                    * =====================================================
                    * ELIMINAR SOLO EL ARCHIVO PARCIAL
                    * =====================================================
                    *
                    * Los archivos anteriores que ya pasaron SHA-256
                    * pusieron este estado a None y se conservan.
                    */
                    let partial_filename =
                        current_partial_filename
                            .lock()
                            .ok()
                            .and_then(
                                |mut partial| {
                                    partial.take()
                                }
                            );


                    if let Some(
                        partial_filename
                    ) =
                        partial_filename
                    {
                        let partial_path =
                            output_directory
                                .join(
                                    &partial_filename
                                );


                        match tokio::fs::remove_file(
                            &partial_path
                        )
                        .await
                        {
                            Ok(()) => {
                                println!(
                                    "[VitaTransfer] Removed partial incoming file: {}",
                                    partial_path.display()
                                );
                            }


                            Err(error)
                                if error.kind()
                                    ==
                                    std::io::ErrorKind::NotFound =>
                            {
                                /*
                                * Si todavía no se había creado físicamente,
                                * no hay nada que eliminar.
                                */
                            }


                            Err(error) => {
                                eprintln!(
                                    "[VitaTransfer] WARNING: Could not remove partial file {}: {}",
                                    partial_path.display(),
                                    error
                                );
                            }
                        }
                    }


                    /*
                    * Cerramos TCP para que la Vita deje también
                    * inmediatamente su lado de la transferencia.
                    */
                    let _ =
                        stream
                            .shutdown()
                            .await;


                    return Ok(());
                }
            };


        match receive_result {
            Ok(stats) => {
                if stats.cancelled {
                    println!(
                        "[VitaTransfer] Incoming Vita batch cancelled"
                    );
                }
                else {
                    println!(
                        "[VitaTransfer] Incoming Vita batch complete: {} file(s), {:.2} MB, {:.2} MB/s",
                        stats.files_received,
                        stats.bytes_received as f64
                            / (1024.0 * 1024.0),
                        stats.megabytes_per_second,
                    );
                }


                transfer::close_session(
                    &mut stream
                )
                .await?;


                println!(
                    "[VitaTransfer] Incoming Vita session completed and released: {}",
                    session_id
                );


                Ok(())
            }


            Err(error) => {
                eprintln!(
                    "[VitaTransfer] Incoming Vita transfer failed for {}: {}",
                    session_id,
                    error
                );


                let _ =
                    transfer::close_session(
                        &mut stream
                    )
                    .await;


                Err(error)
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

pub struct RsVitaTransferProgress {
    pub file_name: String,

    /*
     * Índice basado en 1:
     * 1 de 3, 2 de 3...
     */
    pub file_index: u32,
    pub file_count: u32,

    pub file_bytes_sent: u64,
    pub file_size: u64,

    pub total_bytes_sent: u64,
    pub total_size: u64,

    pub megabytes_per_second: f64,

    /*
     * true solamente cuando toda la sesión
     * ha terminado correctamente.
     */
    pub finished: bool,

    pub canceled: bool,

    /*
     * Si ocurre un error durante el envío,
     * lo mandaremos por el mismo Stream.
     */
    pub error: Option<String>,
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

/* ========================================================= */
/* SESION DE ENVIO VITATRANSFER                              */
/* CON SOPORTE DE PAIRING SAS DESDE FLUTTER                 */
/* ========================================================= */

enum VitaTransferHandshakeState {
    Ready(
        handshake::HandshakeResult,
    ),

    Pairing(
        handshake::PendingPairing,
    ),
}


/*
 * Esta estructura mantiene viva la MISMA conexion TCP
 * mientras Flutter muestra el dialogo SAS.
 *
 * Es fundamental no reconectar durante el pairing:
 *
 * - mismo X25519 efimero
 * - mismo transcript
 * - mismo session_key
 * - mismo codigo SAS
 */
pub struct RsVitaTransferSendSession {
    stream:
        Mutex<Option<tokio::net::TcpStream>>,

    handshake_state:
        Mutex<Option<VitaTransferHandshakeState>>,

    paths:
        Vec<PathBuf>,

    cancel:
        CancellationToken,
}


/*
 * Inicia una sesion VitaTransfer.
 *
 * Si el dispositivo ya es de confianza:
 *
 *     handshake_state = Ready
 *
 * Si necesita pairing:
 *
 *     handshake_state = Pairing
 *
 * En ambos casos mantenemos el TcpStream abierto.
 */
pub async fn start_vitatransfer_send(
    host: String,
    paths: Vec<String>,
) -> anyhow::Result<RsVitaTransferSendSession> {
    if paths.is_empty() {
        anyhow::bail!(
            "No files were provided to VitaTransfer"
        );
    }


    let signing_key =
        identity::load_existing_identity()?;


    let mut stream =
        client::connect(
            &host
        )
        .await?;


    let handshake_status =
        handshake::perform_handshake(
            &mut stream,
            &signing_key,
        )
        .await?;


    let handshake_state =
        match handshake_status {
            HandshakeStatus::Established(
                result
            ) => {
                VitaTransferHandshakeState::Ready(
                    result
                )
            }


            HandshakeStatus::PairingRequired(
                pending
            ) => {
                VitaTransferHandshakeState::Pairing(
                    pending
                )
            }
        };


    let paths =
        paths
            .into_iter()
            .map(PathBuf::from)
            .collect();


    Ok(
        RsVitaTransferSendSession {
            stream:
                Mutex::new(
                    Some(stream)
                ),

            handshake_state:
                Mutex::new(
                    Some(handshake_state)
                ),

            paths,

            cancel:
                CancellationToken::new(),
        }
    )
}


impl RsVitaTransferSendSession {
    /*
     * Devuelve el codigo SAS si esta sesion
     * necesita confirmacion.
     *
     * Si ya existe confianza:
     *
     *     None
     */
    pub async fn pairing_code(
        &self,
    ) -> Option<String> {
        let state =
            self
                .handshake_state
                .lock()
                .await;


        match state.as_ref() {
            Some(
                VitaTransferHandshakeState::Pairing(
                    pending
                )
            ) => {
                Some(
                    pending
                        .pairing_code
                        .clone()
                )
            }


            _ => {
                None
            }
        }
    }


    /*
     * Completa el pairing usando LA MISMA
     * conexion TCP que creo el SAS.
     */
    pub async fn confirm_pairing(
        &self,
        accepted: bool,
    ) -> anyhow::Result<()> {
        let mut state_guard =
            self
                .handshake_state
                .lock()
                .await;


        let state =
            state_guard
                .take()
                .ok_or_else(
                    || {
                        anyhow::anyhow!(
                            "VitaTransfer handshake state is no longer available"
                        )
                    }
                )?;


        match state {
            VitaTransferHandshakeState::Ready(
                result
            ) => {
                /*
                 * Ya estaba emparejado.
                 *
                 * Restauramos el estado y no hacemos nada.
                 */
                *state_guard =
                    Some(
                        VitaTransferHandshakeState::Ready(
                            result
                        )
                    );

                Ok(())
            }


            VitaTransferHandshakeState::Pairing(
                pending
            ) => {
                let mut stream_guard =
                    self
                        .stream
                        .lock()
                        .await;


                let stream =
                    stream_guard
                        .as_mut()
                        .ok_or_else(
                            || {
                                anyhow::anyhow!(
                                    "VitaTransfer connection is no longer available"
                                )
                            }
                        )?;


                /*
                 * Rechazo del usuario.
                 *
                 * finish_pairing(false) envia el byte
                 * correspondiente a Vita.
                 *
                 * El core devuelve error intencionadamente
                 * porque la sesion no puede continuar.
                 *
                 * Para Flutter, cancelar el dialogo no es
                 * un error de aplicacion.
                 */
                if !accepted {
                    /*
                    * Comunicamos el rechazo a Vita,
                    * pero no esperamos su respuesta final.
                    *
                    * Así Cancelar en Flutter es inmediato.
                    */
                    stream
                        .write_all(
                            &[0u8]
                        )
                        .await?;


                    drop(pending);


                    *stream_guard =
                        None;


                    return Ok(());
                }


                /*
                 * Aceptacion.
                 *
                 * Aqui el core:
                 *
                 * - envia PC_ACCEPT
                 * - recibe el resultado de Vita
                 * - persiste trust si corresponde
                 * - completa el handshake
                 */
                let result =
                    handshake::finish_pairing(
                        stream,
                        pending,
                        true,
                    )
                    .await?;


                *state_guard =
                    Some(
                        VitaTransferHandshakeState::Ready(
                            result
                        )
                    );


                Ok(())
            }
        }
    }

    pub fn cancel(
        &self,
    ) {
        self.cancel
            .cancel();
    }

    pub async fn send_with_progress(
        &self,
        sink: StreamSink<RsVitaTransferProgress>,
    ) {
        if let Err(error) =
            self
                .run_send_with_progress(
                    &sink
                )
                .await
        {
            let _ =
                sink.add(
                    RsVitaTransferProgress {
                        file_name:
                            String::new(),

                        file_index:
                            0,

                        file_count:
                            self.paths.len() as u32,

                        file_bytes_sent:
                            0,

                        file_size:
                            0,

                        total_bytes_sent:
                            0,

                        total_size:
                            0,

                        megabytes_per_second:
                            0.0,

                        finished:
                            true,

                        canceled:
                            false,

                        error:
                            Some(
                                error.to_string()
                            ),
                    }
                );
        }
    }

    async fn run_send_with_progress(
        &self,
        sink: &StreamSink<RsVitaTransferProgress>,
    ) -> anyhow::Result<()> {
        /*
        * =====================================================
        * CALCULAR TAMAÑO TOTAL DE LA SESIÓN
        * =====================================================
        */

        let mut total_size:
            u64 = 0;


        for path in &self.paths {
            let size =
                path
                    .metadata()?
                    .len();


            total_size =
                total_size
                    .checked_add(
                        size
                    )
                    .ok_or_else(
                        || {
                            anyhow::anyhow!(
                                "VitaTransfer total size overflow"
                            )
                        }
                    )?;
        }


        let file_count =
            self.paths.len() as u32;


        /*
        * =====================================================
        * OBTENER HANDSHAKE YA COMPLETADO
        * =====================================================
        */

        let mut state_guard =
            self
                .handshake_state
                .lock()
                .await;


        let handshake_result =
            match state_guard.take() {
                Some(
                    VitaTransferHandshakeState::Ready(
                        result
                    )
                ) => {
                    result
                }


                Some(
                    VitaTransferHandshakeState::Pairing(
                        pending
                    )
                ) => {
                    /*
                    * Restauramos el estado.
                    */
                    *state_guard =
                        Some(
                            VitaTransferHandshakeState::Pairing(
                                pending
                            )
                        );


                    anyhow::bail!(
                        "VitaTransfer pairing has not been confirmed yet"
                    );
                }


                None => {
                    anyhow::bail!(
                        "VitaTransfer session has already been consumed"
                    );
                }
            };


        drop(state_guard);


        /*
        * =====================================================
        * CONEXIÓN TCP
        * =====================================================
        */

        let mut stream_guard =
            self
                .stream
                .lock()
                .await;


        let stream =
            stream_guard
                .as_mut()
                .ok_or_else(
                    || {
                        anyhow::anyhow!(
                            "VitaTransfer connection is no longer available"
                        )
                    }
                )?;


        /*
        * Un único estado de nonce para TODA
        * la sesión PC -> Vita.
        */
        let mut send_state =
            transfer::SendState::new()?;


        let mut completed_bytes:
            u64 = 0;


        /*
        * =====================================================
        * ARCHIVOS
        * =====================================================
        */

        for (
            file_zero_index,
            path
        ) in self
            .paths
            .iter()
            .enumerate()
        {
            let file_index =
                file_zero_index as u32
                    + 1;


            let file_size =
                path
                    .metadata()?
                    .len();


            let file_name =
                path
                    .file_name()
                    .and_then(
                        |name| {
                            name.to_str()
                        }
                    )
                    .unwrap_or(
                        "archivo"
                    )
                    .to_string();


            /*
            * Evento inicial.
            *
            * Hace posible que Flutter muestre inmediatamente
            * el nombre del archivo aunque Rust todavía esté
            * calculando el SHA-256.
            */
            let _ =
                sink.add(
                    RsVitaTransferProgress {
                        file_name:
                            file_name.clone(),

                        file_index,

                        file_count,

                        file_bytes_sent:
                            0,

                        file_size,

                        total_bytes_sent:
                            completed_bytes,

                        total_size,

                        megabytes_per_second:
                            0.0,

                        finished:
                            false,

                        canceled:
                            false,

                        error:
                            None,
                    }
                );


            /*
            * =================================================
            * CALLBACK CORE -> BRIDGE
            * =================================================
            */

            let mut progress_callback =
                |progress:
                    transfer::TransferProgress|
                {
                    let session_bytes =
                        completed_bytes
                            .saturating_add(
                                progress
                                    .bytes_sent
                            );


                    let _ =
                        sink.add(
                            RsVitaTransferProgress {
                                file_name:
                                    file_name.clone(),

                                file_index,

                                file_count,

                                file_bytes_sent:
                                    progress
                                        .bytes_sent,

                                file_size:
                                    progress
                                        .total_bytes,

                                total_bytes_sent:
                                    session_bytes,

                                total_size,

                                megabytes_per_second:
                                    progress
                                        .megabytes_per_second,

                                finished:
                                    false,

                                canceled:
                                    false,

                                error:
                                    None,
                            }
                        );
                };


            enum SendOutcome<T> {
                Finished(T),
                Cancelled,
            }


            let outcome =
                tokio::select! {
                    result =
                        transfer::send_file_with_progress(
                            stream,

                            &handshake_result
                                .keys
                                .session_key,

                            &handshake_result
                                .keys
                                .initiator_to_responder_key,

                            &mut send_state,

                            path,

                            Some(
                                &mut progress_callback
                            ),
                        )
                    => {
                        SendOutcome::Finished(
                            result
                        )
                    }


                    _ =
                        self.cancel.cancelled()
                    => {
                        SendOutcome::Cancelled
                    }
                };


            let stats =
                match outcome {
                    SendOutcome::Finished(
                        result
                    ) => {
                        result?
                    }


                    SendOutcome::Cancelled => {
                        /*
                        * Al abandonar send_file_with_progress(),
                        * cerramos el socket.
                        *
                        * Vita detectará la desconexión y abortará
                        * el archivo incompleto.
                        */
                        *stream_guard =
                            None;


                        let _ =
                            sink.add(
                                RsVitaTransferProgress {
                                    file_name:
                                        file_name.clone(),

                                    file_index,

                                    file_count,

                                    file_bytes_sent:
                                        0,

                                    file_size,

                                    total_bytes_sent:
                                        completed_bytes,

                                    total_size,

                                    megabytes_per_second:
                                        0.0,

                                    finished:
                                        true,

                                    canceled:
                                        true,

                                    error:
                                        None,
                                }
                            );


                        return Ok(());
                    }
                };


            completed_bytes =
                completed_bytes
                    .saturating_add(
                        stats.bytes_sent
                    );
        }


        /*
        * =====================================================
        * CIERRE NORMAL
        * =====================================================
        */

        transfer::close_session(
            stream
        )
        .await?;


        *stream_guard =
            None;


        /*
        * Evento final de toda la sesión.
        */
        let _ =
            sink.add(
                RsVitaTransferProgress {
                    file_name:
                        self
                            .paths
                            .last()
                            .and_then(
                                |path| {
                                    path
                                        .file_name()
                                }
                            )
                            .and_then(
                                |name| {
                                    name.to_str()
                                }
                            )
                            .unwrap_or(
                                "archivo"
                            )
                            .to_string(),

                    file_index:
                        file_count,

                    file_count,

                    file_bytes_sent:
                        self
                            .paths
                            .last()
                            .and_then(
                                |path| {
                                    path
                                        .metadata()
                                        .ok()
                                }
                            )
                            .map(
                                |metadata| {
                                    metadata.len()
                                }
                            )
                            .unwrap_or(0),

                    file_size:
                        self
                            .paths
                            .last()
                            .and_then(
                                |path| {
                                    path
                                        .metadata()
                                        .ok()
                                }
                            )
                            .map(
                                |metadata| {
                                    metadata.len()
                                }
                            )
                            .unwrap_or(0),

                    total_bytes_sent:
                        completed_bytes,

                    total_size,

                    megabytes_per_second:
                        0.0,

                    finished:
                        true,

                    canceled:
                        false,

                    error:
                        None,
                }
            );


        Ok(())
    }


    /*
     * Envia todos los archivos una vez que
     * el handshake esta completamente listo.
     */
    pub async fn send(
        &self,
    ) -> anyhow::Result<RsVitaTransferSendResult> {
        let mut state_guard =
            self
                .handshake_state
                .lock()
                .await;


        let handshake_result =
            match state_guard.take() {
                Some(
                    VitaTransferHandshakeState::Ready(
                        result
                    )
                ) => {
                    result
                }


                Some(
                    VitaTransferHandshakeState::Pairing(
                        pending
                    )
                ) => {
                    /*
                     * Todavia no podemos transmitir.
                     * Restauramos el pairing pendiente.
                     */
                    *state_guard =
                        Some(
                            VitaTransferHandshakeState::Pairing(
                                pending
                            )
                        );


                    anyhow::bail!(
                        "VitaTransfer pairing has not been confirmed yet"
                    );
                }


                None => {
                    anyhow::bail!(
                        "VitaTransfer session has already been consumed"
                    );
                }
            };


        /*
         * Ya no necesitamos bloquear el estado del
         * handshake mientras enviamos datos.
         */
        drop(state_guard);


        let mut stream_guard =
            self
                .stream
                .lock()
                .await;


        let stream =
            stream_guard
                .as_mut()
                .ok_or_else(
                    || {
                        anyhow::anyhow!(
                            "VitaTransfer connection is no longer available"
                        )
                    }
                )?;


        /*
         * Un unico estado de nonce para TODA
         * la sesion PC -> Vita.
         */
        let mut send_state =
            transfer::SendState::new()?;


        let mut files_sent:
            u32 = 0;

        let mut bytes_sent:
            u64 = 0;


        for path in &self.paths {
            let stats =
                transfer::send_file(
                    stream,

                    &handshake_result
                        .keys
                        .session_key,

                    &handshake_result
                        .keys
                        .initiator_to_responder_key,

                    &mut send_state,

                    path,
                )
                .await?;


            files_sent +=
                1;

            bytes_sent +=
                stats.bytes_sent;
        }


        transfer::close_session(
            stream
        )
        .await?;


        /*
         * La sesion es one-shot.
         *
         * Despues de SESSION_END ya no debe
         * reutilizarse este socket.
         */
        *stream_guard =
            None;


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
}