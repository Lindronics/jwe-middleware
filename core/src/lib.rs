use biscuit::{
    jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm},
    jwe,
};

pub use biscuit::{jwk::JWK, Empty};

pub fn decrypt_request(body: &[u8], key: &JWK<Empty>) -> Result<Vec<u8>, anyhow::Error> {
    let body = std::str::from_utf8(body)?;

    let token: jwe::Compact<Vec<u8>, Empty> = jwe::Compact::new_encrypted(body);

    let decrypted_jwe = token.decrypt(
        key,
        KeyManagementAlgorithm::A256GCMKW,
        ContentEncryptionAlgorithm::A256GCM,
    )?;

    match decrypted_jwe {
        jwe::Compact::Decrypted { payload, .. } => Ok(payload),
        jwe::Compact::Encrypted(_) => Err(anyhow::anyhow!("Decryption failed")),
    }
}
