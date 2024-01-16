use std::marker::PhantomData;

use biscuit::{
    jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm},
    jwe,
    jwk::JWK,
    Empty,
};

pub trait Encryptor {
    type Error;
    type Key;

    fn encrypt(&self, body: Vec<u8>, key: &Self::Key) -> Result<String, Self::Error>;
}

pub struct DefaultEncryptor<E> {
    e: PhantomData<E>,
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

        let nonce_counter = num_bigint::BigUint::from_bytes_le(&[0; 96 / 8]);
        let mut nonce_bytes = nonce_counter.to_bytes_le();
        nonce_bytes.resize(96 / 8, 0);
        let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };

        // Encrypt
        match token.encrypt(key, &options).map_err(EncryptError::from)? {
            jwe::Compact::Encrypted(encrypted_jwe) => Ok(encrypted_jwe.encode()),
            _ => Err(EncryptError::EncryptionFailed.into()),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Error
////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("Decryption failed")]
    EncryptionFailed,
}

impl From<biscuit::errors::Error> for EncryptError {
    fn from(_e: biscuit::errors::Error) -> Self {
        EncryptError::EncryptionFailed {}
    }
}
