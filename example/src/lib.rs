use std::net::{SocketAddr, TcpListener};

use actix_web::{web, App, HttpServer, ResponseError};
use anyhow::Context;
use jwe_actix_middleware::{
    request::DecryptRequest,
    response::{EncryptResponse, Keystore},
};
use jwe_core::{
    decrypt::default::{DecryptError, DefaultDecryptor},
    encrypt::default::{DefaultEncryptor, EncryptError},
    Empty, JWKSet,
};
use tokio::task::JoinHandle;

pub struct Server {
    pub address: SocketAddr,
    #[allow(dead_code)]
    pub join_handle: JoinHandle<Result<(), std::io::Error>>,
    pub server_key: jwe_core::JWK<Empty>,
    pub keystore: CustomKeystore,
}

impl Default for Server {
    fn default() -> Self {
        let address = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();

        let server_key = jwe_core::JWK::new_octet_key(&[0; 32], Empty {});
        let mut client_key = jwe_core::JWK::new_octet_key(&[0; 32], Empty {});
        client_key.common.key_id = Some("asdf".into());

        let keystore = CustomKeystore {
            keys: jwe_core::JWKSet {
                keys: vec![server_key.clone(), client_key.clone()],
            },
        };

        let decryptor = DefaultDecryptor::<CustomEncryptError>::new(server_key.clone());
        let encryptor = DefaultEncryptor::<CustomEncryptError>::default();
        let keystore_clone = keystore.clone();

        let join_handle = tokio::spawn(
            HttpServer::new(move || {
                App::new().service(
                    web::resource("/")
                        .to(handler)
                        .wrap(DecryptRequest::new(decryptor.clone()))
                        .wrap(EncryptResponse::new(
                            keystore_clone.clone(),
                            encryptor.clone(),
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
}

async fn handler(request: web::Bytes) -> web::Bytes {
    println!("{:?}", String::from_utf8(request.to_vec()));
    request
}

#[derive(Clone)]
pub struct CustomKeystore {
    pub keys: JWKSet<Empty>,
}

impl Keystore for CustomKeystore {
    type Key = jwe_core::JWK<Empty>;
    type Error = CustomEncryptError;

    fn select_key(
        &self,
        request: &actix_web::dev::ServiceRequest,
    ) -> impl std::future::Future<Output = Result<&jwe_core::JWK<Empty>, Self::Error>> + Send {
        let Some(Ok(kid)) = request
            .headers()
            .get("response-kid")
            .map(|kid| kid.to_str())
        else {
            return std::future::ready(Err(anyhow::anyhow!(
                "Missing or invalid response-kid header"
            )
            .into()));
        };
        std::future::ready(
            self.keys
                .find(kid)
                .context("Key not found in key store")
                .map_err(CustomEncryptError::from),
        )
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Decryption failed: {0}")]
pub struct CustomEncryptError(#[from] anyhow::Error);

impl ResponseError for CustomEncryptError {
    fn status_code(&self) -> actix_http::StatusCode {
        actix_http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl From<EncryptError> for CustomEncryptError {
    fn from(value: EncryptError) -> Self {
        Self(value.into())
    }
}

impl From<DecryptError> for CustomEncryptError {
    fn from(value: DecryptError) -> Self {
        Self(value.into())
    }
}
