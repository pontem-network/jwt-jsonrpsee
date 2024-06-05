use std::task::Context;

use eyre::{Result, WrapErr};
use serde::{Deserialize, Serialize};
use rand::prelude::*;
use http::{Request, Response, StatusCode, header::{AUTHORIZATION, HeaderValue}};
use tower::Service;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Claims {
    exp: u64,
    iat: u64,
}

impl Claims {
    pub fn with_expiration(secs: u64) -> Self {
        let iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        Self { iat, exp: iat + secs }
    }
}

pub const JWT_SECRET_LENGTH: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct JwtSecret([u8; JWT_SECRET_LENGTH]);

impl std::fmt::Display for JwtSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::str::FromStr for JwtSecret {
    type Err = eyre::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl rand::distributions::Distribution<JwtSecret> for rand::distributions::Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> JwtSecret {
        JwtSecret::new(rng.gen())
    }
}

impl JwtSecret {
    pub fn new(secret: [u8; JWT_SECRET_LENGTH]) -> Self {
        Self(secret)
    }

    pub fn from_hex(s: impl AsRef<[u8]>) -> Result<Self> {
        let vec = hex::decode(s).context("Jwt secret hex decode")?;
        (&*vec)
            .try_into()
            .map(Self::new)
            .map_err(|_| eyre::eyre!("JWT secret of different length"))
    }

    pub fn decode(&self, token: &str) -> Result<Claims> {
        jsonwebtoken::decode::<Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(&self.0),
            &jsonwebtoken::Validation::default(),
        )
        .map(|data| data.claims)
        .context("Failed to decode claims")
    }

    pub fn claim(&self) -> Result<HeaderValue> {
        let claim = jsonwebtoken::encode(
            &Default::default(),
            // Expires in 30 secs from now
            &Claims::with_expiration(30),
            &jsonwebtoken::EncodingKey::from_secret(&self.0),
        )
        .context("Failed to encode JWT claim")?;
        Ok(HeaderValue::from_str(&claim)
            .expect("Always valid header value from JWT claim"))
    }
}

pub struct ClientLayer(JwtSecret);

impl ClientLayer {
    pub fn new(s: JwtSecret) -> Self {
        Self(s)
    }
}

impl<S> tower::Layer<S> for ClientLayer {
    type Service = ClientAuth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service { inner, jwt: self.0 }
    }
}

#[derive(Clone)]
pub struct ClientAuth<S> {
    inner: S,
    jwt: JwtSecret,
}

impl<S, B> Service<Request<B>> for ClientAuth<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::Either<
        S::Future,
        futures::future::Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Ok(claim) = self.jwt.claim() {
            req.headers_mut()
                .insert(AUTHORIZATION, claim);
        }
        futures::future::Either::Left(self.inner.call(req))
    }
}

pub struct ServerLayer(pub JwtSecret);

impl<S> tower::Layer<S> for ServerLayer {
    type Service = ServerAuth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ServerAuth { inner, jwt: self.0 }
    }
}

pub struct ServerAuth<S> {
    inner: S,
    jwt: JwtSecret,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ServerAuth<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::Either<
        S::Future,
        futures::future::Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let Some(Ok(token)) = req.headers().get(AUTHORIZATION).map(|auth| auth.to_str()) else {
            let response = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Default::default())
                .unwrap();
            return futures::future::Either::Right(futures::future::ok(response));
        };

        if self.jwt.decode(token).is_err() {
            let response = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Default::default())
                .unwrap();

            return futures::future::Either::Right(futures::future::ok(response));
        }

        req.headers_mut().remove(AUTHORIZATION);

        futures::future::Either::Left(self.inner.call(req))
    }
}
