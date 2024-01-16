use std::marker::PhantomData;

use biscuit::{
    jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm},
    jwe,
    jwk::JWK,
    Empty,
};

pub trait Decryptor {
    type Error;

    fn decrypt(&self, body: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub struct DefaultDecryptor<E> {
    key: JWK<Empty>,
    e: PhantomData<E>,
}

impl<E> DefaultDecryptor<E>
where
    E: From<DecryptError>,
{
    pub fn new(key: JWK<Empty>) -> Self {
        Self {
            key,
            e: PhantomData,
        }
    }
}

impl<E> Decryptor for DefaultDecryptor<E>
where
    E: From<DecryptError>,
{
    type Error = E;

    fn decrypt(&self, body: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let body = std::str::from_utf8(body).map_err(DecryptError::from)?;

        let token: jwe::Compact<Vec<u8>, Empty> = jwe::Compact::new_encrypted(body);

        match token
            .decrypt(
                &self.key,
                KeyManagementAlgorithm::A256GCMKW,
                ContentEncryptionAlgorithm::A256GCM,
            )
            .map_err(DecryptError::from)?
        {
            jwe::Compact::Decrypted { payload, .. } => Ok(payload),
            _ => Err(DecryptError::DecryptionFailed.into()),
        }
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
