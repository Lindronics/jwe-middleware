use std::{
    future::{ready, Future, Ready},
    rc::Rc,
};

use actix_http::body::{BoxBody, MessageBody};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use decryptor::{Empty, JWK};
use futures_util::future::LocalBoxFuture;

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("Decryption failed")]
    EncryptionFailed,
}

pub struct EncryptResponse<K> {
    pub keystore: Rc<K>,
}

impl<S: 'static, K> Transform<S, ServiceRequest> for EncryptResponse<K>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S::Future: 'static,
    K: Keystore + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = EncryptResponseMiddleware<S, K>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(EncryptResponseMiddleware {
            service: Rc::new(service),
            keystore: self.keystore.clone(),
        }))
    }
}

pub struct EncryptResponseMiddleware<S, K> {
    service: Rc<S>,
    keystore: Rc<K>,
}

impl<S, K> Service<ServiceRequest> for EncryptResponseMiddleware<S, K>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
    K: Keystore + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let keystore = self.keystore.clone();

        Box::pin(async move {
            let jwk = keystore.select_key(&req).await.unwrap().unwrap();

            let res = svc.call(req).await.unwrap().map_body(|_, body| {
                let body = body.try_into_bytes().unwrap().to_vec();
                let encrypted = decryptor::encrypt(body, jwk).unwrap();
                BoxBody::new(encrypted)
            });

            Ok(res)
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CustomClaims;

pub trait Keystore {
    fn select_key(
        &self,
        request: &ServiceRequest,
    ) -> impl Future<Output = anyhow::Result<Option<&JWK<Empty>>>> + Send;
}
