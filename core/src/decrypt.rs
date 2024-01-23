pub trait Decryptor {
    type Error;

    fn decrypt(&self, body: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

////////////////////////////////////////////////////////////////////////////////
// Default decryptor
////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "biscuit")]
pub mod default {
    use std::marker::PhantomData;

    use biscuit::{
        jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm},
        jwe,
        jwk::JWK,
        Empty,
    };

    use super::Decryptor;

    /// Default decryptor
    ///
    /// [E] is the error type that will be returned
    pub struct DefaultDecryptor<E = DecryptError> {
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
                _ => Err(DecryptError::DecryptionFailed("Invalid state".into()).into()),
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum DecryptError {
        #[error("Invalid body: {0}")]
        InvalidContent(#[from] std::str::Utf8Error),
        #[error("Decryption failed: {0}")]
        DecryptionFailed(String),
    }

    impl From<biscuit::errors::Error> for DecryptError {
        fn from(e: biscuit::errors::Error) -> Self {
            DecryptError::DecryptionFailed(e.to_string())
        }
    }
}
