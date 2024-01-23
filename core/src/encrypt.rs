pub trait Encryptor {
    type Error;
    type Key;

    fn encrypt(&self, body: Vec<u8>, key: &Self::Key) -> Result<String, Self::Error>;
}

////////////////////////////////////////////////////////////////////////////////
// Default encryptor
////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "biscuit")]
pub mod default {
    use std::marker::PhantomData;

    use biscuit::{
        jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm},
        jwe,
        jwk::JWK,
        Empty,
    };
    use rand::Rng;

    use super::Encryptor;

    /// Default encryptor
    ///
    /// [E] is the error type that will be returned
    pub struct DefaultEncryptor<E = EncryptError> {
        e: PhantomData<E>,
    }

    impl<E> Clone for DefaultEncryptor<E> {
        fn clone(&self) -> Self {
            Self { e: PhantomData }
        }
    }

    impl<E> Default for DefaultEncryptor<E>
    where
        E: From<EncryptError>,
    {
        fn default() -> Self {
            Self { e: PhantomData }
        }
    }

    impl<E> Encryptor for DefaultEncryptor<E>
    where
        E: From<EncryptError>,
    {
        type Error = E;
        type Key = JWK<Empty>;

        fn encrypt(&self, body: Vec<u8>, key: &Self::Key) -> Result<String, Self::Error> {
            let token = jwe::Compact::new_decrypted(
                From::from(jwe::RegisteredHeader {
                    cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
                    enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                    ..Default::default()
                }),
                body,
            );

            let nonce = rand::thread_rng().gen::<[u8; 96 / 8]>().to_vec();
            let options = EncryptionOptions::AES_GCM { nonce };

            match token.encrypt(key, &options).map_err(EncryptError::from)? {
                jwe::Compact::Encrypted(encrypted_jwe) => Ok(encrypted_jwe.encode()),
                _ => Err(EncryptError::EncryptionFailed("Invalid state".into()).into()),
            }
        }
    }

    #[derive(Clone, Debug, thiserror::Error)]
    pub enum EncryptError {
        #[error("Encryption failed: {0}")]
        EncryptionFailed(String),
    }

    impl From<biscuit::errors::Error> for EncryptError {
        fn from(e: biscuit::errors::Error) -> Self {
            EncryptError::EncryptionFailed(e.to_string())
        }
    }
}
