use std::{
    net::{SocketAddr, TcpListener},
    rc::Rc,
};

use actix_middleware::{request::DecryptRequest, response::EncryptResponse};
use actix_web::{web, App, HttpServer};
use biscuit::{
    jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm},
    jwe, Empty,
};
use tokio::task::JoinHandle;

struct Server {
    address: SocketAddr,
    #[allow(dead_code)]
    join_handle: JoinHandle<Result<(), std::io::Error>>,
    server_key: decryptor::JWK<decryptor::Empty>,
    client_key: decryptor::JWK<decryptor::Empty>,
}

async fn handler(request: web::Bytes) -> web::Bytes {
    println!("{:?}", String::from_utf8(request.to_vec()));
    request
}

fn actix_server() -> Server {
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();

    let server_key = decryptor::JWK::new_octet_key(&[0; 32], decryptor::Empty {});
    let client_key = decryptor::JWK::new_octet_key(&[0; 32], decryptor::Empty {});

    let server_key_clone = server_key.clone();
    let client_key_clone = server_key.clone();

    let join_handle = tokio::spawn(
        HttpServer::new(move || {
            App::new().service(
                web::resource("/")
                    .to(handler)
                    .wrap(DecryptRequest {
                        jwk: Rc::new(server_key_clone.clone()),
                    })
                    .wrap(EncryptResponse {
                        jwk: Rc::new(client_key_clone.clone()),
                    }),
            )
        })
        .bind(address)
        .unwrap()
        .run(),
    );

    Server {
        address,
        join_handle,
        server_key,
        client_key,
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

    let jwe::Compact::Encrypted(encrypted_jwe) = jwe.encrypt(&server.server_key, &options).unwrap()
    else {
        panic!()
    };
    let encrypted_body = encrypted_jwe.encode();

    let response = reqwest::Client::new()
        .post(&format!("http://{}", server.address))
        .body(encrypted_body)
        .send()
        .await
        .unwrap();
    let response_body = response.text().await.unwrap();

    dbg!(&response_body);

    let token: jwe::Compact<Vec<u8>, Empty> = jwe::Compact::new_encrypted(&response_body);

    let jwe::Compact::Decrypted { payload, .. } = token
        .decrypt(
            &server.client_key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )
        .unwrap()
    else {
        panic!()
    };

    let response_body: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(response_body, request_body);
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PrivateHeader {}
