use std::path::Path;
use std::time::Instant;

use anyhow::{
    anyhow,
    bail,
    Context,
    Result,
};

use chacha20poly1305::{
    aead::{
        Aead,
        Payload,
    },
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

use tokio::fs::{
    self,
    File,
};

use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};

use tokio::net::TcpStream;

use super::protocol::{
    CHUNK_SIZE,
    COMMAND_REQUEST_RESPONDER_FILE,
    MAX_FILENAME_SIZE,
    META_MAC_LABEL,
    RESPONDER_BATCH_BEGIN,
    RESPONDER_BATCH_CANCELLED,
    RESPONDER_BATCH_END,
    RESPONDER_FILE_OFFER_ERROR,
    RESPONDER_FILE_OFFER_OK,
    TRANSFER_READY,
    TRANSFER_RESULT_ERROR,
    TRANSFER_RESULT_OK,
    BATCH_MANIFEST_MAC_LABEL,
    RESPONDER_BATCH_MANIFEST,
};

type HmacSha256 = Hmac<Sha256>;

const MAX_BATCH_FILES: u16 = 64;

pub struct ReceivedFileStats {
    pub filename: String,
    pub bytes_received: u64,
    pub elapsed_seconds: f64,
    pub megabytes_per_second: f64,
}

pub struct BatchReceiveStats {
    pub files_received: usize,
    pub bytes_received: u64,
    pub elapsed_seconds: f64,
    pub megabytes_per_second: f64,
    pub cancelled: bool,
}

#[derive(Debug, Clone)]
pub struct BatchReceiveProgress {
    pub filename: String,

    /*
     * Índice basado en 1:
     * 1 de 2, 2 de 2...
     */
    pub file_number: u16,
    pub file_count: u16,

    pub file_bytes_received: u64,
    pub file_size: u64,

    pub megabytes_per_second: f64,

    /*
     * true cuando ESTE archivo ha terminado
     * correctamente y ha pasado SHA-256.
     */
    pub file_finished: bool,
}

#[derive(Debug, Clone)]
pub struct BatchManifestFile {
    pub filename: String,
    pub size: u64,
}


#[derive(Debug, Clone)]
pub struct BatchManifest {
    pub files:
        Vec<BatchManifestFile>,
}

fn validate_filename(
    filename: &str,
) -> Result<()> {
    if filename.is_empty() {
        bail!(
            "Received an empty filename"
        );
    }

    if filename == "."
        || filename == ".."
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains(':')
        || filename
            .chars()
            .any(|character| {
                (character as u32) < 32
            })
    {
        bail!(
            "Received invalid filename: {filename}"
        );
    }

    Ok(())
}

fn verify_metadata_hmac(
    session_key: &[u8; 32],
    filename_len_raw: &[u8; 2],
    filename_raw: &[u8],
    filesize_raw: &[u8; 8],
    expected_sha256: &[u8; 32],
    received_mac: &[u8; 32],
) -> Result<()> {
    /*
     * Debe ser exactamente:
     *
     * HMAC-SHA256(
     *     session_key,
     *
     *     META_MAC_LABEL
     *     + filename_len
     *     + filename
     *     + filesize
     *     + expected_sha256
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
        filename_len_raw
    );

    mac.update(
        filename_raw
    );

    mac.update(
        filesize_raw
    );

    mac.update(
        expected_sha256
    );

    mac.verify_slice(
        received_mac
    )
    .map_err(|_| {
        anyhow!(
            "Metadata HMAC verification failed"
        )
    })?;

    Ok(())
}

pub async fn receive_batch_manifest(
    stream: &mut TcpStream,
    session_key: &[u8; 32],
) -> Result<BatchManifest> {
    let mut marker =
        [0u8; 1];


    stream
        .read_exact(
            &mut marker
        )
        .await
        .context(
            "Could not receive Vita batch manifest marker"
        )?;


    if marker[0] !=
        RESPONDER_BATCH_MANIFEST
    {
        bail!(
            "Expected Vita batch manifest 0x{:02X}, received 0x{:02X}",
            RESPONDER_BATCH_MANIFEST,
            marker[0],
        );
    }


    let mut count_raw =
        [0u8; 2];


    stream
        .read_exact(
            &mut count_raw
        )
        .await
        .context(
            "Could not receive Vita manifest file count"
        )?;


    let count =
        u16::from_be_bytes(
            count_raw
        );


    if count == 0 ||
        count > MAX_BATCH_FILES
    {
        bail!(
            "Invalid Vita manifest file count: {count}"
        );
    }


    let mut mac =
        <HmacSha256 as HmacKeyInit>
            ::new_from_slice(
                session_key
            )
            .map_err(
                |_| {
                    anyhow!(
                        "Could not initialize manifest HMAC"
                    )
                }
            )?;


    mac.update(
        BATCH_MANIFEST_MAC_LABEL
    );


    mac.update(
        &count_raw
    );


    let mut files =
        Vec::with_capacity(
            count as usize
        );


    for _ in 0..count {
        let mut name_len_raw =
            [0u8; 2];


        stream
            .read_exact(
                &mut name_len_raw
            )
            .await?;


        let name_len =
            u16::from_be_bytes(
                name_len_raw
            ) as usize;


        if name_len == 0 ||
            name_len > MAX_FILENAME_SIZE
        {
            bail!(
                "Invalid Vita manifest filename length: {name_len}"
            );
        }


        let mut name_raw =
            vec![
                0u8;
                name_len
            ];


        stream
            .read_exact(
                &mut name_raw
            )
            .await?;


        let filename =
            String::from_utf8(
                name_raw.clone()
            )
            .context(
                "Vita manifest filename is not UTF-8"
            )?;


        validate_filename(
            &filename
        )?;


        let mut size_raw =
            [0u8; 8];


        stream
            .read_exact(
                &mut size_raw
            )
            .await?;


        let size =
            u64::from_be_bytes(
                size_raw
            );


        mac.update(
            &name_len_raw
        );

        mac.update(
            &name_raw
        );

        mac.update(
            &size_raw
        );


        files.push(
            BatchManifestFile {
                filename,
                size,
            }
        );
    }


    let mut received_mac =
        [0u8; 32];


    stream
        .read_exact(
            &mut received_mac
        )
        .await
        .context(
            "Could not receive Vita manifest HMAC"
        )?;


    mac.verify_slice(
        &received_mac
    )
    .map_err(
        |_| {
            anyhow!(
                "Vita batch manifest HMAC verification failed"
            )
        }
    )?;


    Ok(
        BatchManifest {
            files,
        }
    )
}

async fn receive_offered_file<F>(
    stream: &mut TcpStream,
    session_key: &[u8; 32],
    receive_key: &[u8; 32],
    output_directory: &Path,
    file_number: u16,
    file_count: u16,
    on_progress: &mut F,
) -> Result<ReceivedFileStats>
where
    F: FnMut(BatchReceiveProgress),
{
    /*
     * =====================================================
     * METADATA
     * =====================================================
     */

    let mut filename_len_raw =
        [0u8; 2];

    stream
        .read_exact(
            &mut filename_len_raw
        )
        .await
        .context(
            "Could not receive filename length"
        )?;

    let filename_len =
        u16::from_be_bytes(
            filename_len_raw
        ) as usize;

    if filename_len == 0
        || filename_len > MAX_FILENAME_SIZE
    {
        bail!(
            "Invalid filename length received: {filename_len}"
        );
    }

    let mut filename_raw =
        vec![
            0u8;
            filename_len
        ];

    stream
        .read_exact(
            &mut filename_raw
        )
        .await
        .context(
            "Could not receive filename"
        )?;

    let filename =
        String::from_utf8(
            filename_raw.clone()
        )
        .context(
            "Received filename is not valid UTF-8"
        )?;

    validate_filename(
        &filename
    )?;

    let mut filesize_raw =
        [0u8; 8];

    stream
        .read_exact(
            &mut filesize_raw
        )
        .await
        .context(
            "Could not receive file size"
        )?;

    let filesize =
        u64::from_be_bytes(
            filesize_raw
        );

    let mut expected_sha256 =
        [0u8; 32];

    stream
        .read_exact(
            &mut expected_sha256
        )
        .await
        .context(
            "Could not receive expected SHA-256"
        )?;

    let mut received_mac =
        [0u8; 32];

    stream
        .read_exact(
            &mut received_mac
        )
        .await
        .context(
            "Could not receive metadata HMAC"
        )?;

    verify_metadata_hmac(
        session_key,
        &filename_len_raw,
        &filename_raw,
        &filesize_raw,
        &expected_sha256,
        &received_mac,
    )?;

    println!();
    println!(
        "========================================"
    );
    println!(
        "VITA -> PC [{file_number}/{file_count}]"
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
        "Metadata HMAC: OK"
    );
    println!(
        "========================================"
    );

    /*
     * =====================================================
     * DESTINO
     * =====================================================
     */

    fs::create_dir_all(
        output_directory
    )
    .await
    .with_context(|| {
        format!(
            "Could not create receive directory {}",
            output_directory.display()
        )
    })?;

    let output_path =
        output_directory
            .join(
                &filename
            );

    println!(
        "Destino: {}",
        output_path.display()
    );

    /*
    * Evento inicial del archivo.
    *
    * Además de permitir que Flutter conozca el archivo
    * desde 0 bytes, nos será útil para eliminar el parcial
    * correctamente al cancelar.
    */
    on_progress(
        BatchReceiveProgress {
            filename:
                filename.clone(),

            file_number,
            file_count,

            file_bytes_received:
                0,

            file_size:
                filesize,

            megabytes_per_second:
                0.0,

            file_finished:
                false,
        }
    );

    /*
     * =====================================================
     * AVISAR A VITA:
     *
     * metadata aceptada,
     * estamos preparados.
     * =====================================================
     */

    stream
        .write_all(
            &[TRANSFER_READY]
        )
        .await
        .context(
            "Could not send TRANSFER_READY"
        )?;

    /*
     * =====================================================
     * CHACHA20-POLY1305
     * =====================================================
     */

    let cipher =
        ChaCha20Poly1305
            ::new_from_slice(
                receive_key
            )
            .map_err(|_| {
                anyhow!(
                    "Invalid ChaCha20-Poly1305 receive key"
                )
            })?;

    let start =
        Instant::now();

    /*
     * Todo lo que ocurra después de TRANSFER_READY
     * debe terminar enviando OK o ERROR a la Vita.
     */

    let receive_result:
        Result<(u64, [u8; 32])> =
        async {
            let mut output =
                File::create(
                    &output_path
                )
                .await
                .with_context(|| {
                    format!(
                        "Could not create {}",
                        output_path.display()
                    )
                })?;

            let mut actual_hash =
                Sha256::new();

            let mut total_received =
                0u64;

            loop {
                /*
                 * Header:
                 *
                 * uint32 big endian =
                 * longitud plaintext.
                 *
                 * También es el AAD.
                 */

                let mut header =
                    [0u8; 4];

                stream
                    .read_exact(
                        &mut header
                    )
                    .await
                    .context(
                        "Could not receive chunk header"
                    )?;

                let plaintext_len =
                    u32::from_be_bytes(
                        header
                    ) as usize;

                /*
                 * 00000000 = EOF
                 */

                if plaintext_len == 0 {
                    break;
                }

                if plaintext_len
                    > CHUNK_SIZE
                {
                    bail!(
                        "Received chunk is too large: {plaintext_len} bytes"
                    );
                }

                let new_total =
                    total_received
                        .checked_add(
                            plaintext_len
                                as u64
                        )
                        .context(
                            "Received byte counter overflow"
                        )?;

                if new_total
                    > filesize
                {
                    bail!(
                        "Vita sent more data than declared"
                    );
                }

                /*
                 * Nonce IETF:
                 * 12 bytes.
                 */

                let mut nonce_bytes =
                    [0u8; 12];

                stream
                    .read_exact(
                        &mut nonce_bytes
                    )
                    .await
                    .context(
                        "Could not receive chunk nonce"
                    )?;

                /*
                 * ciphertext + Poly1305 tag
                 */

                let encrypted_len =
                    plaintext_len
                        .checked_add(16)
                        .context(
                            "Encrypted chunk length overflow"
                        )?;

                let mut encrypted =
                    vec![
                        0u8;
                        encrypted_len
                    ];

                stream
                    .read_exact(
                        &mut encrypted
                    )
                    .await
                    .context(
                        "Could not receive encrypted chunk"
                    )?;

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
                 * Python:
                 *
                 * decrypt(
                 *     nonce,
                 *     encrypted,
                 *     header
                 * )
                 *
                 * header es AAD.
                 */

                let plaintext =
                    cipher
                        .decrypt(
                            &nonce,

                            Payload {
                                msg:
                                    &encrypted,

                                aad:
                                    &header,
                            },
                        )
                        .map_err(|_| {
                            anyhow!(
                                "ChaCha20-Poly1305 authentication failed"
                            )
                        })?;

                if plaintext.len()
                    != plaintext_len
                {
                    bail!(
                        "Decrypted chunk has incorrect length"
                    );
                }

                output
                    .write_all(
                        &plaintext
                    )
                    .await
                    .context(
                        "Could not write received file"
                    )?;

                actual_hash.update(
                    &plaintext
                );

                total_received =
                    new_total;

                let elapsed =
                    start
                        .elapsed()
                        .as_secs_f64();

                let received_mb =
                    total_received as f64
                        / (1024.0 * 1024.0);

                let total_mb =
                    filesize as f64
                        / (1024.0 * 1024.0);

                let percent =
                    if filesize > 0 {
                        total_received as f64
                            / filesize as f64
                            * 100.0
                    } else {
                        100.0
                    };

                let speed =
                    if elapsed > 0.0 {
                        received_mb
                            / elapsed
                    } else {
                        0.0
                    };

                println!(
                    "{received_mb:.2} / {total_mb:.2} MB   {percent:6.2}%   {speed:.2} MB/s"
                );

                on_progress(
                    BatchReceiveProgress {
                        filename:
                            filename.clone(),

                        file_number,
                        file_count,

                        file_bytes_received:
                            total_received,

                        file_size:
                            filesize,

                        megabytes_per_second:
                            speed,

                        file_finished:
                            false,
                    }
                );
            }

            output
                .flush()
                .await
                .context(
                    "Could not flush received file"
                )?;

            let digest =
                actual_hash
                    .finalize();

            let mut actual_sha256 =
                [0u8; 32];

            actual_sha256
                .copy_from_slice(
                    &digest
                );

            Ok(
                (
                    total_received,
                    actual_sha256,
                )
            )
        }
        .await;

    /*
     * =====================================================
     * ERROR DURANTE RECEPCION
     * =====================================================
     */

    let (
        total_received,
        actual_sha256,
    ) =
        match receive_result {
            Ok(result) => {
                result
            }

            Err(error) => {
                let _ =
                    stream
                        .write_all(
                            &[
                                TRANSFER_RESULT_ERROR
                            ]
                        )
                        .await;

                let _ =
                    fs::remove_file(
                        &output_path
                    )
                    .await;

                return Err(
                    error
                );
            }
        };

    /*
     * =====================================================
     * SHA-256 FINAL
     * =====================================================
     */

    let integrity_ok =
        total_received
            == filesize
        && actual_sha256
            == expected_sha256;

    if !integrity_ok {
        stream
            .write_all(
                &[
                    TRANSFER_RESULT_ERROR
                ]
            )
            .await
            .context(
                "Could not send transfer ERROR"
            )?;

        let _ =
            fs::remove_file(
                &output_path
            )
            .await;

        bail!(
            "Received file does not match announced SHA-256"
        );
    }

    /*
     * =====================================================
     * ACK OK
     * =====================================================
     */

    stream
        .write_all(
            &[TRANSFER_RESULT_OK]
        )
        .await
        .context(
            "Could not send transfer OK"
        )?;

    let elapsed_seconds =
        start
            .elapsed()
            .as_secs_f64();

    let megabytes =
        total_received as f64
            / (1024.0 * 1024.0);

    let megabytes_per_second =
        if elapsed_seconds > 0.0 {
            megabytes
                / elapsed_seconds
        } else {
            0.0
        };

    on_progress(
        BatchReceiveProgress {
            filename:
                filename.clone(),

            file_number,
            file_count,

            file_bytes_received:
                total_received,

            file_size:
                filesize,

            megabytes_per_second,

            file_finished:
                true,
        }
    );

    println!();
    println!(
        "========================================"
    );
    println!(
        "VITA -> PC SUCCESS"
    );
    println!(
        "SHA-256 VERIFIED"
    );
    println!(
        "========================================"
    );
    println!(
        "Guardado en: {}",
        output_path.display()
    );
    println!(
        "Tiempo: {:.2} s",
        elapsed_seconds
    );
    println!(
        "Velocidad efectiva: {:.2} MB/s",
        megabytes_per_second
    );

    Ok(
        ReceivedFileStats {
            filename,
            bytes_received:
                total_received,
            elapsed_seconds,
            megabytes_per_second,
        }
    )
}

pub async fn receive_batch_with_progress<F>(
    stream: &mut TcpStream,
    session_key: &[u8; 32],
    receive_key: &[u8; 32],
    output_directory: &Path,
    on_progress: &mut F,
) -> Result<BatchReceiveStats>
where
    F: FnMut(BatchReceiveProgress),
{
    /*
     * =====================================================
     * PEDIR ARCHIVOS A LA VITA
     * =====================================================
     */

    println!();
    println!(
        "Abriendo selector de archivos en Vita..."
    );

    stream
        .write_all(
            &[
                COMMAND_REQUEST_RESPONDER_FILE
            ]
        )
        .await
        .context(
            "Could not request files from Vita"
        )?;

    let mut response =
        [0u8; 1];

    stream
        .read_exact(
            &mut response
        )
        .await
        .context(
            "Could not receive batch response"
        )?;

    /*
     * Usuario canceló el selector.
     */

    if response[0]
        == RESPONDER_BATCH_CANCELLED
    {
        println!(
            "Selección cancelada en Vita."
        );

        return Ok(
            BatchReceiveStats {
                files_received: 0,
                bytes_received: 0,
                elapsed_seconds: 0.0,
                megabytes_per_second: 0.0,
                cancelled: true,
            }
        );
    }

    if response[0]
        != RESPONDER_BATCH_BEGIN
    {
        bail!(
            "Unknown batch start response: 0x{:02X}",
            response[0]
        );
    }

    /*
     * Cantidad de archivos:
     * uint16 big endian.
     */

    let mut file_count_raw =
        [0u8; 2];

    stream
        .read_exact(
            &mut file_count_raw
        )
        .await
        .context(
            "Could not receive batch file count"
        )?;

    let file_count =
        u16::from_be_bytes(
            file_count_raw
        );

    if file_count == 0
        || file_count
            > MAX_BATCH_FILES
    {
        bail!(
            "Invalid batch file count: {file_count}"
        );
    }

    println!();
    println!(
        "========================================"
    );
    println!(
        "LOTE VITA -> PC"
    );
    println!(
        "Archivos seleccionados: {file_count}"
    );
    println!(
        "========================================"
    );

    let batch_start =
        Instant::now();

    let mut batch_bytes =
        0u64;

    let mut batch_files =
        0usize;

    /*
     * =====================================================
     * ARCHIVOS DEL LOTE
     * =====================================================
     */

    for file_number in
        1..=file_count
    {
        let mut offer =
            [0u8; 1];

        stream
            .read_exact(
                &mut offer
            )
            .await
            .context(
                "Could not receive Vita file offer"
            )?;

        if offer[0]
            == RESPONDER_FILE_OFFER_ERROR
        {
            bail!(
                "Vita could not prepare file {file_number}/{file_count}"
            );
        }

        if offer[0]
            != RESPONDER_FILE_OFFER_OK
        {
            bail!(
                "Unknown file offer response: 0x{:02X}",
                offer[0]
            );
        }

        let stats =
            receive_offered_file(
                stream,
                session_key,
                receive_key,
                output_directory,
                file_number,
                file_count,
                on_progress,
            )
            .await?;

        batch_files += 1;

        batch_bytes +=
            stats.bytes_received;
    }

    /*
     * =====================================================
     * BATCH END
     * =====================================================
     */

    let mut batch_end =
        [0u8; 1];

    stream
        .read_exact(
            &mut batch_end
        )
        .await
        .context(
            "Could not receive batch end"
        )?;

    if batch_end[0]
        != RESPONDER_BATCH_END
    {
        bail!(
            "Invalid batch end: expected 0x{:02X}, received 0x{:02X}",
            RESPONDER_BATCH_END,
            batch_end[0],
        );
    }

    let elapsed_seconds =
        batch_start
            .elapsed()
            .as_secs_f64();

    let megabytes =
        batch_bytes as f64
            / (1024.0 * 1024.0);

    let megabytes_per_second =
        if elapsed_seconds > 0.0 {
            megabytes
                / elapsed_seconds
        } else {
            0.0
        };

    println!();
    println!(
        "========================================"
    );
    println!(
        "BATCH SUCCESS"
    );
    println!(
        "Archivos verificados: {batch_files}"
    );
    println!(
        "Datos recibidos: {:.2} MB",
        megabytes
    );
    println!(
        "Tiempo del lote: {:.2} s",
        elapsed_seconds
    );
    println!(
        "Velocidad media: {:.2} MB/s",
        megabytes_per_second
    );
    println!(
        "========================================"
    );

    Ok(
        BatchReceiveStats {
            files_received:
                batch_files,

            bytes_received:
                batch_bytes,

            elapsed_seconds,

            megabytes_per_second,

            cancelled:
                false,
        }
    )
}

/*
 * =========================================================
 * API COMPATIBLE SIN PROGRESO
 * =========================================================
 *
 * Conservamos receive_batch() para que todo el código
 * existente siga funcionando exactamente igual.
 *
 * Más adelante accept_incoming_with_progress() utilizará
 * receive_batch_with_progress().
 */
pub async fn receive_batch(
    stream: &mut TcpStream,
    session_key: &[u8; 32],
    receive_key: &[u8; 32],
    output_directory: &Path,
) -> Result<BatchReceiveStats> {
    let mut ignore_progress =
        |_progress: BatchReceiveProgress| {
        };


    receive_batch_with_progress(
        stream,
        session_key,
        receive_key,
        output_directory,
        &mut ignore_progress,
    )
    .await
}