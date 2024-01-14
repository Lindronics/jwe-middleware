use std::{
    future::{ready, Ready},
    rc::Rc,
};

use actix_http::body::{BoxBody, MessageBody};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use decryptor::{Empty, JWK};
use futures_util::future::LocalBoxFuture;

pub struct EncryptResponse {
    pub jwk: Rc<JWK<Empty>>,
}

impl<S: 'static> Transform<S, ServiceRequest> for EncryptResponse
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = EncryptResponseMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(EncryptResponseMiddleware {
            service: Rc::new(service),
            jwk: self.jwk.clone(),
        }))
    }
}

pub struct EncryptResponseMiddleware<S> {
    service: Rc<S>,
    jwk: Rc<JWK<Empty>>,
}

impl<S> Service<ServiceRequest> for EncryptResponseMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let jwk = self.jwk.clone();

        Box::pin(async move {
            let res = svc.call(req).await.unwrap().map_body(|_, body| {
                let body = body.try_into_bytes().unwrap().to_vec();
                let encrypted = decryptor::encrypt(body, &jwk).unwrap();
                BoxBody::new(encrypted)
            });

            Ok(res)
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CustomClaims;
