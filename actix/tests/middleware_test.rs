use std::net::{SocketAddr, TcpListener};

use actix_middleware::{
    request::{DecryptError, DecryptRequest},
    response::{EncryptError, EncryptResponse, Keystore},
};
use actix_web::{web, App, HttpServer, ResponseError};
use biscuit::{
    jwa::{ContentEncryptionAlgorithm, EncryptionOptions, KeyManagementAlgorithm},
    jwe,
    jwk::JWKSet,
    Empty,
};
use tokio::task::JoinHandle;

#[derive(Clone)]
struct CustomKeystore {
    keys: JWKSet<Empty>,
}

impl Keystore for CustomKeystore {
    type Error = anyhow::Error;

    fn select_key(
        &self,
        request: &actix_web::dev::ServiceRequest,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<&jwe_core::JWK<Empty>>>> + Send
    {
        let kid = request.headers().get("response-kid").unwrap();
        std::future::ready(Ok(self.keys.find(kid.to_str().unwrap())))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Decryption failed")]
struct CustomEncryptError;

impl ResponseError for CustomEncryptError {
    fn status_code(&self) -> actix_http::StatusCode {
        actix_http::StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_http::body::BoxBody> {
        todo!()
    }
}

impl From<EncryptError<anyhow::Error>> for CustomEncryptError {
    fn from(_value: EncryptError<anyhow::Error>) -> Self {
        todo!()
    }
}

impl From<DecryptError> for CustomEncryptError {
    fn from(_value: DecryptError) -> Self {
        todo!()
    }
}

struct Server {
    address: SocketAddr,
    #[allow(dead_code)]
    join_handle: JoinHandle<Result<(), std::io::Error>>,
    server_key: jwe_core::JWK<jwe_core::Empty>,
    keystore: CustomKeystore,
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

    let server_key = jwe_core::JWK::new_octet_key(&[0; 32], jwe_core::Empty {});
    let mut client_key = jwe_core::JWK::new_octet_key(&[0; 32], jwe_core::Empty {});
    client_key.common.key_id = Some("asdf".into());

    let keystore = CustomKeystore {
        keys: JWKSet {
            keys: vec![server_key.clone(), client_key.clone()],
        },
    };

    let server_key_clone = server_key.clone();
    let keystore_clone = keystore.clone();

    let join_handle = tokio::spawn(
        HttpServer::new(move || {
            App::new().service(
                web::resource("/")
                    .to(handler)
                    .wrap(DecryptRequest::<CustomEncryptError>::new(
                        server_key_clone.clone(),
                    ))
                    .wrap(EncryptResponse::<CustomKeystore, CustomEncryptError>::new(
                        keystore_clone.clone(),
                    )),
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
        keystore,
    }
}

#[tokio::test]
async fn middleware_works() {
    let server = actix_server();
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
