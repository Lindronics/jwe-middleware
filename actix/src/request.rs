use std::{
    future::{ready, Ready},
    marker::PhantomData,
    rc::Rc,
};

use actix_http::h1;
use actix_web::{
    dev::{self, forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web, Error, ResponseError,
};
use futures_util::future::LocalBoxFuture;
use jwe_core::{Empty, JWK};

////////////////////////////////////////////////////////////////////////////////
// Middlware
////////////////////////////////////////////////////////////////////////////////

pub struct DecryptRequest<E> {
    jwk: Rc<JWK<Empty>>,
    e: PhantomData<E>,
}

impl<E> DecryptRequest<E> {
    pub fn new(jwk: JWK<Empty>) -> Self {
        Self {
            jwk: Rc::new(jwk),
            e: PhantomData,
        }
    }
}

impl<S, B, E> Transform<S, ServiceRequest> for DecryptRequest<E>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    E: ResponseError + From<DecryptError> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = DecryptRequestMiddleware<S, E>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DecryptRequestMiddleware {
            service: Rc::new(service),
            jwk: self.jwk.clone(),
            e: PhantomData,
        }))
    }
}

pub struct DecryptRequestMiddleware<S, E> {
    service: Rc<S>,
    jwk: Rc<JWK<Empty>>,
    e: PhantomData<E>,
}

impl<S, B, E> Service<ServiceRequest> for DecryptRequestMiddleware<S, E>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    E: ResponseError + From<DecryptError> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let jwk = self.jwk.clone();

        Box::pin(async move {
            let body = req.extract::<web::Bytes>().await?;

            let decrypted_body = jwe_core::decrypt(&body, &jwk)
                .map_err(DecryptError::from)
                .map_err(E::from)?;

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

////////////////////////////////////////////////////////////////////////////////
// Error
////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error(transparent)]
    DecryptionFailed(#[from] jwe_core::DecryptError),
}
