use biscuit::{
    jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm},
    jwe,
    jwk::JWK,
    Empty,
};

pub fn decrypt(body: &[u8], key: &JWK<Empty>) -> Result<Vec<u8>, DecryptError> {
    let body = std::str::from_utf8(body)?;

    let token: jwe::Compact<Vec<u8>, Empty> = jwe::Compact::new_encrypted(body);

    match token.decrypt(
        key,
        KeyManagementAlgorithm::A256GCMKW,
        ContentEncryptionAlgorithm::A256GCM,
    )? {
        jwe::Compact::Decrypted { payload, .. } => Ok(payload),
        _ => Err(DecryptError::DecryptionFailed),
    }
}

////////////////////////////////////////////////////////////////////////////////
// Error
////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("Invalid body")]
    InvalidContent,
    #[error("Decryption failed")]
    DecryptionFailed,
}

impl From<std::str::Utf8Error> for DecryptError {
    fn from(_e: std::str::Utf8Error) -> Self {
        DecryptError::InvalidContent {}
    }
}

impl From<biscuit::errors::Error> for DecryptError {
    fn from(_e: biscuit::errors::Error) -> Self {
        DecryptError::DecryptionFailed {}
    }
}
