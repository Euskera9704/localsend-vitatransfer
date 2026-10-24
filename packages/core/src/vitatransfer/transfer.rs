use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use anyhow::{
    anyhow,
    bail,
    Context,
    Result,
};

use chacha20poly1305::{
    aead::AeadInOut,
    ChaCha20Poly1305,
    KeyInit,
    Nonce,
};

use hmac::{
    Hmac,
    KeyInit as HmacKeyInit,
    Mac,
};

use sha2::{
    Digest,
    Sha256,
};

use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};

use tokio::net::TcpStream;

use super::protocol::{
    CHUNK_SIZE,
    COMMAND_FILE,
    COMMAND_FILE_STREAMING,
    INITIATOR_FILE_FINAL_DIGEST,
    COMMAND_SESSION_END,
    I2R_FINAL_DIGEST_MAC_LABEL,
    I2R_STREAM_META_MAC_LABEL,
    MAX_FILENAME_SIZE,
    METADATA_READY,
    META_MAC_LABEL,
    SESSION_END_ACK,
    TRANSFER_READY,
    TRANSFER_RESULT_ERROR,
    TRANSFER_RESULT_OK,
};

type HmacSha256 = Hmac<Sha256>;

pub struct SendState {
    nonce_prefix: [u8; 4],
    block_counter: u64,
}

pub struct TransferStats {
    pub bytes_sent: u64,
    pub elapsed_seconds: f64,
    pub megabytes_per_second: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct TransferProgress {
    pub bytes_sent: u64,
    pub total_bytes: u64,
    pub elapsed_seconds: f64,
    pub megabytes_per_second: f64,
}

impl SendState {
    pub fn new() -> Result<Self> {
        /*
         * Igual que el Python:
         *
         * un prefijo aleatorio de 4 bytes
         * para TODA la sesión.
         *
         * Los otros 8 bytes serán un
         * contador que nunca reiniciamos.
         */

        let mut nonce_prefix =
            [0u8; 4];

        getrandom::fill(
            &mut nonce_prefix
        )
        .map_err(|error| {
            anyhow!(
                "Could not generate VitaTransfer nonce prefix: {error}"
            )
        })?;

        Ok(
            Self {
                nonce_prefix,
                block_counter: 0,
            }
        )
    }

    fn next_nonce(
        &mut self,
    ) -> Result<[u8; 12]> {
        let mut nonce =
            [0u8; 12];

        nonce[..4]
            .copy_from_slice(
                &self.nonce_prefix
            );

        nonce[4..]
            .copy_from_slice(
                &self
                    .block_counter
                    .to_be_bytes()
            );

        self.block_counter =
            self.block_counter
                .checked_add(1)
                .ok_or_else(|| {
                    anyhow!(
                        "VitaTransfer nonce counter exhausted"
                    )
                })?;

        Ok(nonce)
    }
}

fn calculate_sha256(
    path: &Path,
) -> Result<[u8; 32]> {
    let mut file =
        File::open(
            path
        )
        .with_context(|| {
            format!(
                "Could not open {} for SHA-256",
                path.display()
            )
        })?;

    let mut hasher =
        Sha256::new();

    /*
     * Nuestro Python usa bloques
     * de 4 MB para calcular SHA-256.
     */
    let mut buffer =
        vec![
            0u8;
            4 * 1024 * 1024
        ];

    loop {
        let count =
            file.read(
                &mut buffer
            )
            .with_context(|| {
                format!(
                    "Could not read {} while calculating SHA-256",
                    path.display()
                )
            })?;

        if count == 0 {
            break;
        }

        hasher.update(
            &buffer[..count]
        );
    }

    let digest =
        hasher.finalize();

    let mut result =
        [0u8; 32];

    result.copy_from_slice(
        &digest
    );

    Ok(result)
}

fn metadata_hmac(
    session_key: &[u8; 32],
    filename_len: &[u8; 2],
    filename: &[u8],
    filesize: &[u8; 8],
    sha256: &[u8; 32],
) -> Result<[u8; 32]> {
    /*
     * Python:
     *
     * HMAC-SHA256(
     *     session_key,
     *
     *     META_MAC_LABEL
     *     + filename_len
     *     + filename
     *     + filesize
     *     + SHA256
     * )
     */

    let mut mac =
        <HmacSha256 as HmacKeyInit>
            ::new_from_slice(
                session_key
            )
            .map_err(|_| {
                anyhow!(
                    "Could not initialize metadata HMAC"
                )
            })?;

    mac.update(
        META_MAC_LABEL
    );

    mac.update(
        filename_len
    );

    mac.update(
        filename
    );

    mac.update(
        filesize
    );

    mac.update(
        sha256
    );

    let digest =
        mac.finalize()
            .into_bytes();

    let mut result =
        [0u8; 32];

    result.copy_from_slice(
        &digest
    );

    Ok(result)
}

fn streaming_metadata_hmac(
    session_key: &[u8; 32],
    filename_len: &[u8; 2],
    filename: &[u8],
    filesize: &[u8; 8],
) -> Result<[u8; 32]> {
    /*
     * PC -> Vita streaming:
     *
     * HMAC-SHA256(
     *     session_key,
     *
     *     I2R_STREAM_META_MAC_LABEL
     *     + filename_len
     *     + filename
     *     + filesize
     * )
     *
     * No incluye SHA-256 porque todavía
     * no se ha calculado.
     */

    let mut mac =
        <HmacSha256 as HmacKeyInit>
            ::new_from_slice(
                session_key
            )
            .map_err(|_| {
                anyhow!(
                    "Could not initialize streaming metadata HMAC"
                )
            })?;


    mac.update(
        I2R_STREAM_META_MAC_LABEL
    );

    mac.update(
        filename_len
    );

    mac.update(
        filename
    );

    mac.update(
        filesize
    );


    let digest =
        mac.finalize()
            .into_bytes();


    let mut result =
        [0u8; 32];

    result.copy_from_slice(
        &digest
    );


    Ok(result)
}


fn final_digest_hmac(
    session_key: &[u8; 32],
    filename_len: &[u8; 2],
    filename: &[u8],
    filesize: &[u8; 8],
    sha256: &[u8; 32],
) -> Result<[u8; 32]> {
    /*
     * PC -> Vita streaming:
     *
     * HMAC-SHA256(
     *     session_key,
     *
     *     I2R_FINAL_DIGEST_MAC_LABEL
     *     + filename_len
     *     + filename
     *     + filesize
     *     + SHA256_final
     * )
     */

    let mut mac =
        <HmacSha256 as HmacKeyInit>
            ::new_from_slice(
                session_key
            )
            .map_err(|_| {
                anyhow!(
                    "Could not initialize final digest HMAC"
                )
            })?;


    mac.update(
        I2R_FINAL_DIGEST_MAC_LABEL
    );

    mac.update(
        filename_len
    );

    mac.update(
        filename
    );

    mac.update(
        filesize
    );

    mac.update(
        sha256
    );


    let digest =
        mac.finalize()
            .into_bytes();


    let mut result =
        [0u8; 32];

    result.copy_from_slice(
        &digest
    );


    Ok(result)
}

pub async fn send_file_with_progress(
    stream: &mut TcpStream,
    session_key: &[u8; 32],
    send_key: &[u8; 32],
    state: &mut SendState,
    path: &Path,
    mut on_progress: Option<
        &mut (
            dyn FnMut(TransferProgress)
                + Send
        )
    >,
) -> Result<TransferStats> {
    /*
     * =====================================================
     * VALIDAR ARCHIVO
     * =====================================================
     */

    if !path.is_file() {
        bail!(
            "File does not exist: {}",
            path.display()
        );
    }

    let filename =
        path.file_name()
            .context(
                "File has no filename"
            )?
            .to_str()
            .context(
                "Filename is not valid Unicode"
            )?;

    let filename_raw =
        filename.as_bytes();

    if filename_raw.is_empty()
        || filename_raw.len()
            > MAX_FILENAME_SIZE
    {
        bail!(
            "Filename length is invalid: {} bytes",
            filename_raw.len()
        );
    }

    let filesize =
        path.metadata()
            .with_context(|| {
                format!(
                    "Could not read metadata for {}",
                    path.display()
                )
            })?
            .len();

    println!();
    println!(
        "========================================"
    );
    println!(
        "PC -> VITA"
    );
    println!(
        "Archivo: {filename}"
    );
    println!(
        "Tamaño: {:.2} MB",
        filesize as f64
            / (1024.0 * 1024.0)
    );
    println!(
        "========================================"
    );

    /*
    * =====================================================
    * COMMAND_FILE_STREAMING
    * =====================================================
    *
    * Ya no calculamos SHA-256 antes de empezar.
    *
    * El hash se irá construyendo con los mismos bytes
    * que leemos para cifrar y enviar.
    */

    stream
        .write_all(
            &[COMMAND_FILE_STREAMING]
        )
        .await
        .context(
            "Could not send COMMAND_FILE_STREAMING"
        )?;

    let mut metadata_ready =
        [0u8; 1];

    stream
        .read_exact(
            &mut metadata_ready
        )
        .await
        .context(
            "Could not receive METADATA_READY"
        )?;

    if metadata_ready[0]
        != METADATA_READY
    {
        bail!(
            "Invalid METADATA_READY: expected 0x{:02X}, received 0x{:02X}",
            METADATA_READY,
            metadata_ready[0],
        );
    }

    println!(
        "METADATA_READY received."
    );

    /*
     * =====================================================
     * METADATA
     * =====================================================
     */

    let filename_len_raw =
        (filename_raw.len() as u16)
            .to_be_bytes();

    let filesize_raw =
        filesize.to_be_bytes();

    let metadata_mac =
        streaming_metadata_hmac(
            session_key,
            &filename_len_raw,
            filename_raw,
            &filesize_raw,
        )?;

    stream
        .write_all(
            &filename_len_raw
        )
        .await?;

    stream
        .write_all(
            filename_raw
        )
        .await?;

    stream
        .write_all(
            &filesize_raw
        )
        .await?;

    stream
        .write_all(
            &metadata_mac
        )
        .await?;

    /*
     * =====================================================
     * TRANSFER_READY
     * =====================================================
     */

    let mut transfer_ready =
        [0u8; 1];

    stream
        .read_exact(
            &mut transfer_ready
        )
        .await
        .context(
            "Could not receive TRANSFER_READY"
        )?;

    if transfer_ready[0]
        != TRANSFER_READY
    {
        bail!(
            "Invalid TRANSFER_READY: expected 0x{:02X}, received 0x{:02X}",
            TRANSFER_READY,
            transfer_ready[0],
        );
    }

    println!(
        "TRANSFER_READY received."
    );

    /*
     * =====================================================
     * CHACHA20-POLY1305
     * =====================================================
     */

    let cipher =
        ChaCha20Poly1305
            ::new_from_slice(
                send_key
            )
            .map_err(|_| {
                anyhow!(
                    "Invalid ChaCha20-Poly1305 key"
                )
            })?;

    let mut file =
        File::open(
            path
        )
        .with_context(|| {
            format!(
                "Could not open {} for transfer",
                path.display()
            )
        })?;

    let mut plaintext =
        vec![
            0u8;
            CHUNK_SIZE
        ];
    /*
    * SHA-256 calculado simultáneamente
    * con la transferencia.
    */
    let mut hasher =
        Sha256::new();

    let start =
        Instant::now();

    let mut total_sent =
        0u64;

    /*
    * El primer chunk es pequeño para que la transferencia
    * empiece visualmente casi de inmediato.
    *
    * A partir del segundo volvemos al tamaño normal de
    * 16 MiB para conservar el throughput.
    */
    let mut first_chunk =
        true;

    loop {
        let read_size =
            if first_chunk {
                1 * 1024 * 1024
            } else {
                CHUNK_SIZE
            };

        let count =
            file.read(
                &mut plaintext[..read_size]
            )
            .with_context(|| {
                format!(
                    "Could not read {} during transfer",
                    path.display()
                )
            })?;

        if count == 0 {
            break;
        }

        /*
        * Exactamente los mismos bytes que vamos
        * a cifrar y enviar alimentan el SHA-256.
        */
        hasher.update(
            &plaintext[..count]
        );

        /*
         * Header de 4 bytes big-endian.
         *
         * También es el AAD de ChaCha.
         */
        let header =
            (count as u32)
                .to_be_bytes();

        let nonce_bytes =
            state.next_nonce()?;

        let nonce:
            Nonce =
            nonce_bytes
                .as_slice()
                .try_into()
                .map_err(|_| {
                    anyhow!(
                        "Could not build ChaCha20-Poly1305 nonce"
                    )
                })?;

        /*
         * encrypt_in_place añade al Vec
         * el tag Poly1305 de 16 bytes.
         *
         * Resultado:
         *
         * ciphertext || tag
         */
        let mut encrypted =
            plaintext[..count]
                .to_vec();

        cipher
            .encrypt_in_place(
                &nonce,
                &header,
                &mut encrypted,
            )
            .map_err(|_| {
                anyhow!(
                    "ChaCha20-Poly1305 encryption failed"
                )
            })?;

        /*
         * Wire format:
         *
         * header       4 bytes
         * nonce       12 bytes
         * ciphertext   N bytes
         * tag         16 bytes
         */

        stream
            .write_all(
                &header
            )
            .await
            .context(
                "Could not send chunk header"
            )?;

        stream
            .write_all(
                &nonce_bytes
            )
            .await
            .context(
                "Could not send chunk nonce"
            )?;

        stream
            .write_all(
                &encrypted
            )
            .await
            .context(
                "Could not send encrypted chunk"
            )?;

        total_sent +=
            count as u64;

        first_chunk =
            false;

        let elapsed =
            start.elapsed()
                .as_secs_f64();

        let sent_mb =
            total_sent as f64
                / (1024.0 * 1024.0);

        let total_mb =
            filesize as f64
                / (1024.0 * 1024.0);

        let percent =
            if filesize > 0 {
                total_sent as f64
                    / filesize as f64
                    * 100.0
            } else {
                100.0
            };

        let speed =
            if elapsed > 0.0 {
                sent_mb / elapsed
            } else {
                0.0
            };

        if let Some(
            callback
        ) = on_progress.as_mut() {
            callback(
                TransferProgress {
                    bytes_sent:
                        total_sent,

                    total_bytes:
                        filesize,

                    elapsed_seconds:
                        elapsed,

                    megabytes_per_second:
                        speed,
                }
            );
        }


        println!(
            "{sent_mb:.2} / {total_mb:.2} MB   {percent:6.2}%   {speed:.2} MB/s"
        );
    }

    /*
     * =====================================================
     * EOF
     * =====================================================
     */

    stream
        .write_all(
            &[0u8; 4]
        )
        .await
        .context(
            "Could not send file EOF"
        )?;


    /*
    * =====================================================
    * SHA-256 FINAL
    * =====================================================
    *
    * El archivo ya se ha leído exactamente una vez.
    */

    let digest =
        hasher.finalize();

    let mut final_sha256 =
        [0u8; 32];

    final_sha256.copy_from_slice(
        &digest
    );


    /*
    * Autenticamos el digest final con la clave
    * maestra de sesión.
    */
    let final_mac =
        final_digest_hmac(
            session_key,
            &filename_len_raw,
            filename_raw,
            &filesize_raw,
            &final_sha256,
        )?;


    /*
    * =====================================================
    * DIGEST FINAL PC -> VITA
    * =====================================================
    *
    * B9
    * SHA-256       32 bytes
    * HMAC-SHA256   32 bytes
    */

    stream
        .write_all(
            &[INITIATOR_FILE_FINAL_DIGEST]
        )
        .await
        .context(
            "Could not send final digest marker"
        )?;


    stream
        .write_all(
            &final_sha256
        )
        .await
        .context(
            "Could not send final SHA-256"
        )?;


    stream
        .write_all(
            &final_mac
        )
        .await
        .context(
            "Could not send final digest HMAC"
        )?;


    println!(
        "Archivo enviado. Esperando verificación SHA-256 de Vita..."
    );

    /*
     * =====================================================
     * RESULTADO FINAL
     * =====================================================
     */

    let mut transfer_result =
        [0u8; 1];

    stream
        .read_exact(
            &mut transfer_result
        )
        .await
        .context(
            "Could not receive transfer result"
        )?;

    let elapsed_seconds =
        start.elapsed()
            .as_secs_f64();

    let megabytes =
        filesize as f64
            / (1024.0 * 1024.0);

    let megabytes_per_second =
        if elapsed_seconds > 0.0 {
            megabytes
                / elapsed_seconds
        } else {
            0.0
        };

    match transfer_result[0] {
        TRANSFER_RESULT_OK => {
            println!();
            println!(
                "========================================"
            );
            println!(
                "TRANSFER SUCCESS"
            );
            println!(
                "SHA-256 VERIFIED BY VITA"
            );
            println!(
                "========================================"
            );
            println!(
                "Tiempo: {:.2} s",
                elapsed_seconds
            );
            println!(
                "Velocidad efectiva: {:.2} MB/s",
                megabytes_per_second
            );
        }

        TRANSFER_RESULT_ERROR => {
            bail!(
                "Vita rejected file integrity"
            );
        }

        other => {
            bail!(
                "Unknown transfer result: 0x{other:02X}"
            );
        }
    }

    Ok(
        TransferStats {
            bytes_sent:
                total_sent,

            elapsed_seconds,

            megabytes_per_second,
        }
    )
}

pub async fn send_file(
    stream: &mut TcpStream,
    session_key: &[u8; 32],
    send_key: &[u8; 32],
    state: &mut SendState,
    path: &Path,
) -> Result<TransferStats> {
    send_file_with_progress(
        stream,
        session_key,
        send_key,
        state,
        path,
        None,
    )
    .await
}

pub async fn close_session(
    stream: &mut TcpStream,
) -> Result<()> {
    stream
        .write_all(
            &[COMMAND_SESSION_END]
        )
        .await
        .context(
            "Could not send COMMAND_SESSION_END"
        )?;

    let mut ack =
        [0u8; 1];

    stream
        .read_exact(
            &mut ack
        )
        .await
        .context(
            "Could not receive SESSION_END_ACK"
        )?;

    if ack[0]
        != SESSION_END_ACK
    {
        bail!(
            "Invalid SESSION_END_ACK: expected 0x{:02X}, received 0x{:02X}",
            SESSION_END_ACK,
            ack[0],
        );
    }

    println!(
        "Session closed cleanly."
    );

    Ok(())
}