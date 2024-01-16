use std::{
    future::{ready, Future, Ready},
    rc::Rc,
};

use actix_http::body::{BoxBody, MessageBody};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, ResponseError,
};
use futures_util::future::LocalBoxFuture;
use jwe_core::encrypt::Encryptor;

////////////////////////////////////////////////////////////////////////////////
// Middleware
////////////////////////////////////////////////////////////////////////////////

pub struct EncryptResponse<K, E> {
    keystore: Rc<K>,
    encryptor: Rc<E>,
}

impl<K, E> EncryptResponse<K, E>
where
    K: Keystore,
    E: Encryptor,
{
    pub fn new(keystore: K, encryptor: E) -> Self
    where
        K: Keystore,
    {
        EncryptResponse {
            keystore: Rc::new(keystore),
            encryptor: Rc::new(encryptor),
        }
    }
}

impl<S: 'static, K, E> Transform<S, ServiceRequest> for EncryptResponse<K, E>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    K: Keystore + 'static,
    K::Error: ResponseError,
    E: Encryptor<Key = K::Key> + 'static,
    E::Error: ResponseError,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = EncryptResponseMiddleware<S, K, E>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(EncryptResponseMiddleware {
            service: Rc::new(service),
            keystore: self.keystore.clone(),
            encryptor: self.encryptor.clone(),
        }))
    }
}

pub struct EncryptResponseMiddleware<S, K, E> {
    service: Rc<S>,
    keystore: Rc<K>,
    encryptor: Rc<E>,
}

impl<S, K, E> Service<ServiceRequest> for EncryptResponseMiddleware<S, K, E>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    K: Keystore + 'static,
    K::Error: ResponseError,
    E: Encryptor<Key = K::Key> + 'static,
    E::Error: ResponseError,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let keystore = self.keystore.clone();
        let encryptor = self.encryptor.clone();

        Box::pin(async move {
            let jwk = keystore.select_key(&req).await?;

            let res = svc.call(req).await?.map_body(|_, body| {
                let body = match body.try_into_bytes().map(|b| b.to_vec()) {
                    Ok(body) => body,
                    Err(e) => return e.boxed(),
                };
                let encrypted = match encryptor.encrypt(body, jwk) {
                    Ok(encrypted) => encrypted,
                    Err(e) => return e.error_response().into_body(),
                };
                BoxBody::new(encrypted)
            });

            Ok(res)
        })
    }
}

////////////////////////////////////////////////////////////////////////////////
// Keystore
////////////////////////////////////////////////////////////////////////////////

pub trait Keystore {
    type Error: std::fmt::Debug;
    type Key;

    fn select_key(
        &self,
        request: &ServiceRequest,
    ) -> impl Future<Output = Result<&Self::Key, Self::Error>> + Send;
}
