pub const PORT: u16 = 5000;

pub const SESSION_READY: u8 = 0xC0;

pub const COMMAND_FILE: u8 = 0x01;
pub const COMMAND_SESSION_END: u8 = 0x02;
pub const COMMAND_REQUEST_RESPONDER_FILE: u8 = 0x03;

pub const METADATA_READY: u8 = 0xB0;

pub const RESPONDER_FILE_OFFER_OK: u8 = 0xB1;
pub const RESPONDER_FILE_OFFER_ERROR: u8 = 0xB2;

pub const RESPONDER_BATCH_BEGIN: u8 = 0xB3;
pub const RESPONDER_BATCH_END: u8 = 0xB4;
pub const RESPONDER_BATCH_CANCELLED: u8 = 0xB5;
pub const RESPONDER_BATCH_MANIFEST:
    u8 = 0xB6;

pub const BATCH_MANIFEST_MAC_LABEL:
    &[u8] =
        b"VFT-BATCH-MANIFEST-v1";

pub const TRANSFER_READY: u8 = 0xA5;

pub const TRANSFER_RESULT_OK: u8 = 0x01;
pub const TRANSFER_RESULT_ERROR: u8 = 0x00;

pub const SESSION_END_ACK: u8 = 0xD0;

pub const PROTOCOL_LABEL: &[u8] =
    b"VFT-PAIR-HS-v1";

pub const HKDF_SALT: &[u8] =
    b"VFT-HKDF-SALT-v1";

pub const HKDF_INFO: &[u8] =
    b"VFT-SESSION-v1";

pub const PAIR_LABEL: &[u8] =
    b"VFT-PAIR-CODE-v1";

pub const META_MAC_LABEL: &[u8] =
    b"VFT-METADATA-MAC-v1";

pub const DATA_I2R_LABEL: &[u8] =
    b"VFT-DATA-INITIATOR-TO-RESPONDER-v1";

pub const DATA_R2I_LABEL: &[u8] =
    b"VFT-DATA-RESPONDER-TO-INITIATOR-v1";

pub const SESSION_KEY_SIZE: usize = 32;

pub const CHUNK_SIZE: usize =
    16 * 1024 * 1024;

pub const MAX_FILENAME_SIZE: usize = 255;