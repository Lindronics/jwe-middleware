use std::{
    future::{ready, Ready},
    rc::Rc,
};

use actix_http::h1;
use actix_web::{
    dev::{self, forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web::{self},
    Error,
};
use decryptor::{Empty, JWK};
use futures_util::future::LocalBoxFuture;

pub struct RequestEncryption {
    pub jwk: Rc<JWK<Empty>>,
}

impl<S: 'static, B> Transform<S, ServiceRequest> for RequestEncryption
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SayHiMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SayHiMiddleware {
            service: Rc::new(service),
            jwk: self.jwk.clone(),
        }))
    }
}

pub struct SayHiMiddleware<S> {
    service: Rc<S>,
    jwk: Rc<JWK<Empty>>,
}

impl<S, B> Service<ServiceRequest> for SayHiMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let jwk = self.jwk.clone();

        Box::pin(async move {
            let body = req.extract::<web::Bytes>().await.unwrap();

            let decrypted_body = decryptor::decrypt_request(&body, &jwk).unwrap();

            req.set_payload(bytes_to_payload(decrypted_body.into()));

            svc.call(req).await
        })
    }
}

fn bytes_to_payload(buf: web::Bytes) -> dev::Payload {
    let (_, mut pl) = h1::Payload::create(true);
    pl.unread_data(buf);
    dev::Payload::from(pl)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CustomClaims;
