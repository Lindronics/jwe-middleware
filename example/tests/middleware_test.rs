use biscuit::{
    jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm},
    jwe, Empty,
};
use example::Server;

#[tokio::test]
async fn middlewares_work() {
    let server = Server::default();
    let client_key = server.keystore.keys.keys[1].clone();
    let request_body = serde_json::json!({"hello": "world"});

    // Encrypt request
    let plaintext = serde_json::ser::to_vec(&request_body).unwrap();
    let jwe = jwe::Compact::new_decrypted(
        From::from(jwe::RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            ..Default::default()
        }),
        plaintext,
    );

    let nonce_counter = num_bigint::BigUint::from_bytes_le(&[0; 96 / 8]);
    let mut nonce_bytes = nonce_counter.to_bytes_le();
    nonce_bytes.resize(96 / 8, 0);
    let options = EncryptionOptions::AES_GCM { nonce: nonce_bytes };

    let jwe::Compact::Encrypted(encrypted_jwe) = jwe.encrypt(&server.server_key, &options).unwrap()
    else {
        panic!()
    };
    let encrypted_body = encrypted_jwe.encode();

    // Send request
    let response = reqwest::Client::new()
        .post(&format!("http://{}", server.address))
        .body(encrypted_body)
        .header("response-kid", client_key.common.key_id.clone().unwrap())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // Decrypt response
    let token = jwe::Compact::<Vec<u8>, Empty>::new_encrypted(&response);

    let jwe::Compact::Decrypted { payload, .. } = token
        .decrypt(
            &client_key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap()
    else {
        panic!()
    };

    let response_body = serde_json::from_slice::<serde_json::Value>(&payload).unwrap();
    assert_eq!(response_body, request_body);
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PrivateHeader {}
