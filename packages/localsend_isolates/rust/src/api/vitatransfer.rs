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

use tokio::io::AsyncWriteExt;
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