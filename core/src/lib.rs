use biscuit::{
    jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm},
    jwe,
};

pub use biscuit::{jwk::JWK, Empty};

pub fn decrypt(body: &[u8], key: &JWK<Empty>) -> Result<Vec<u8>, anyhow::Error> {
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

pub fn encrypt(body: Vec<u8>, key: &JWK<Empty>) -> Result<String, anyhow::Error> {
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
    let jwe::Compact::Encrypted(encrypted_jwe) = token.encrypt(key, &options).unwrap() else {
        panic!()
    };
    let encrypted_body = encrypted_jwe.encode();
    Ok(encrypted_body)
}
