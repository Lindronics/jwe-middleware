use std::{
    net::{SocketAddr, TcpListener},
    rc::Rc,
};

use actix_middleware::{request::DecryptRequest, response::EncryptResponse};
use actix_web::{web, App, HttpServer};
use biscuit::{
    jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm},
    jwe,
};
use serde_json::json;
use tokio::task::JoinHandle;

struct Server {
    address: SocketAddr,
    _join_handle: JoinHandle<Result<(), std::io::Error>>,
    jwk: decryptor::JWK<decryptor::Empty>,
}

fn actix_server() -> Server {
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();

    let jwk = decryptor::JWK::new_octet_key(&[0; 32], decryptor::Empty {});

    let jwk_clone = jwk.clone();
    let join_handle = tokio::spawn(
        HttpServer::new(move || {
            App::new().service(
                web::resource("/")
                    .to(|| async { "{\"hello world\": \"a\"}" })
                    .wrap(DecryptRequest {
                        jwk: Rc::new(jwk_clone.clone()),
                    })
                    .wrap(EncryptResponse {
                        jwk: Rc::new(jwk_clone.clone()),
                    }),
            )
        })
        .bind(address)
        .unwrap()
        .run(),
    );

    Server {
        address,
        _join_handle: join_handle,
        jwk,
    }
}

#[tokio::test]
async fn middleware_works() {
    let server = actix_server();

    let request_body = serde_json::json!({"hello": "world"});
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

    // Encrypt
    let jwe::Compact::Encrypted(encrypted_jwe) = jwe.encrypt(&server.jwk, &options).unwrap() else {
        panic!()
    };
    let encrypted_body = encrypted_jwe.encode();
    dbg!(&encrypted_body);

    let response = reqwest::Client::new()
        .post(&format!("http://{}", server.address))
        .body(encrypted_body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let response_body = response.text().await.unwrap();
    assert_eq!(response_body, json!({"hello world": "a"}));
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PrivateHeader {}
