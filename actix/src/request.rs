use std::{
    future::{ready, Ready},
    rc::Rc,
};

use actix_http::h1;
use actix_web::{
    dev::{self, forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web, Error, ResponseError,
};
use futures_util::future::LocalBoxFuture;
use jwe_core::Decryptor;

////////////////////////////////////////////////////////////////////////////////
// Middlware
////////////////////////////////////////////////////////////////////////////////

pub struct DecryptRequest<D> {
    decryptor: Rc<D>,
}

impl<D> DecryptRequest<D>
where
    D: Decryptor,
{
    pub fn new(decryptor: D) -> Self
    where
        D: Decryptor,
        D::Error: ResponseError,
    {
        Self {
            decryptor: Rc::new(decryptor),
        }
    }
}

impl<S, D> Transform<S, ServiceRequest> for DecryptRequest<D>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    D: Decryptor + 'static,
    D::Error: ResponseError,
{
    type Response = ServiceResponse;
    type Error = Error;
    type InitError = ();
    type Transform = DecryptRequestMiddleware<S, D>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DecryptRequestMiddleware {
            service: Rc::new(service),
            decryptor: self.decryptor.clone(),
        }))
    }
}

pub struct DecryptRequestMiddleware<S, D> {
    service: Rc<S>,
    decryptor: Rc<D>,
}

impl<S, D> Service<ServiceRequest> for DecryptRequestMiddleware<S, D>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    D: Decryptor + 'static,
    D::Error: ResponseError,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        let decryptor = self.decryptor.clone();

        Box::pin(async move {
            let body = req.extract::<web::Bytes>().await?;

            let decrypted_body = decryptor.decrypt(&body)?;

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
