use std::{
    future::{ready, Future, Ready},
    marker::PhantomData,
    rc::Rc,
};

use actix_http::body::{BoxBody, MessageBody};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, ResponseError,
};
use decryptor::{Empty, JWK};
use futures_util::future::LocalBoxFuture;

#[derive(Debug, thiserror::Error)]
pub enum EncryptError<K> {
    #[error("Decryption failed")]
    EncryptionFailed,
    #[error("Keystore could not be accessed: {0}")]
    KeystoreError(K),
    #[error("Key could not be found")]
    KeyNotFound,
}

pub struct EncryptResponse<K, E> {
    keystore: Rc<K>,
    error: PhantomData<E>,
}

impl<K, E> EncryptResponse<K, E>
where
    K: Keystore,
    E: ResponseError + From<EncryptError<K::Error>>,
{
    pub fn new(keystore: K) -> Self
    where
        K: Keystore,
    {
        EncryptResponse {
            keystore: Rc::new(keystore),
            error: PhantomData,
        }
    }
}

impl<S: 'static, K, E> Transform<S, ServiceRequest> for EncryptResponse<K, E>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    K: Keystore + 'static,
    E: ResponseError + From<EncryptError<K::Error>> + 'static,
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
            error: PhantomData,
        }))
    }
}

pub struct EncryptResponseMiddleware<S, K, E> {
    service: Rc<S>,
    keystore: Rc<K>,
    error: PhantomData<E>,
}

impl<S, K, E> Service<ServiceRequest> for EncryptResponseMiddleware<S, K, E>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    K: Keystore + 'static,
    E: ResponseError + From<EncryptError<K::Error>> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let keystore = self.keystore.clone();

        Box::pin(async move {
            let jwk = keystore
                .select_key(&req)
                .await
                .map_err(EncryptError::KeystoreError)
                .map_err(E::from)?
                .ok_or(EncryptError::KeyNotFound)
                .map_err(E::from)?;

            let res = svc.call(req).await.unwrap().map_body(|_, body| {
                let body = body.try_into_bytes().unwrap().to_vec();
                let encrypted = decryptor::encrypt(body, jwk).unwrap();
                BoxBody::new(encrypted)
            });

            Ok(res)
        })
    }
}

pub trait Keystore {
    type Error;

    fn select_key(
        &self,
        request: &ServiceRequest,
    ) -> impl Future<Output = Result<Option<&JWK<Empty>>, Self::Error>> + Send;
}
