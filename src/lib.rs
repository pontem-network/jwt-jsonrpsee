use std::task::Context;

use headers::authorization::{Bearer, Credentials};
use http::{
    header::{HeaderValue, AUTHORIZATION},
    Request, Response, StatusCode,
};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use tower::Service;

const CLAIM_EXPIRATION: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Decoding JWT from hex failed ")]
    DecodeJwtHex(
        #[from]
        #[source]
        hex::FromHexError,
    ),
    #[error("Decoding JWT failed expected length {JWT_SECRET_LENGTH}, but got {0}")]
    DecodeJwtLength(usize),
    #[error("Decoding claim failed")]
    DecodeClaim(#[source] jsonwebtoken::errors::Error),
    #[error("Decoding claim failed")]
    EncodeClaim(#[source] jsonwebtoken::errors::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Claims {
    exp: u64,
    iat: u64,
}

impl Claims {
    pub fn with_expiration(secs: u64) -> Self {
        let iat = now();
        Self {
            iat,
            exp: iat + secs,
        }
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
    type Err = Error;
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
        let vec = hex::decode(s)?;
        (&*vec)
            .try_into()
            .map(Self::new)
            .map_err(|_| Error::DecodeJwtLength(vec.len()))
    }

    pub fn decode(&self, token: &str) -> Result<Claims> {
        jsonwebtoken::decode::<Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(&self.0),
            &jsonwebtoken::Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(Error::DecodeClaim)
    }

    pub fn to_bearer(&self) -> Result<HeaderValue> {
        let claim = jsonwebtoken::encode(
            &Default::default(),
            // Expires in 30 secs from now
            &Claims::with_expiration(CLAIM_EXPIRATION),
            &jsonwebtoken::EncodingKey::from_secret(&self.0),
        )
        .map_err(Error::EncodeClaim)?;

        Ok(
            HeaderValue::from_str(&format!("{} {claim}", Bearer::SCHEME))
                .expect("Always valid header value from JWT claim"),
        )
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
        if let Ok(claim) = self.jwt.to_bearer() {
            req.headers_mut().insert(AUTHORIZATION, claim);
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
        let unauthorized = || -> Self::Future {
            let response = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Default::default())
                .unwrap();
            futures::future::Either::Right(futures::future::ok(response))
        };

        let Some(Ok(auth_str)) = req.headers().get(AUTHORIZATION).map(|auth| auth.to_str()) else {
            return unauthorized();
        };

        let bearer_len = Bearer::SCHEME.len();
        if auth_str
            .to_lowercase()
            .strip_prefix(&Bearer::SCHEME.to_lowercase())
            .is_none()
        {
            return unauthorized();
        }

        let token = auth_str[bearer_len..].trim();

        let Ok(claim) = self.jwt.decode(token) else {
            return unauthorized();
        };

        if claim.exp < now() {
            return unauthorized();
        }

        req.headers_mut().remove(AUTHORIZATION);

        futures::future::Either::Left(self.inner.call(req))
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

#[cfg(test)]
mod test {
    use std::{convert::Infallible, time::Duration};

    use http::{header::AUTHORIZATION, Request};
    use http::{Response, StatusCode};

    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use jsonrpsee::RpcModule;

    use tokio::time::sleep;
    use tower::{Service, ServiceExt};

    use tracing::{debug, instrument};

    use crate::{ClientLayer, JwtSecret, ServerLayer, CLAIM_EXPIRATION};

    #[instrument(level = "debug")]
    async fn handle(req: Request<&str>) -> Result<Response<&str>, Infallible> {
        debug!("Request processing");

        Ok(Response::new("success"))
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_tower_jwt() {
        let jwt_secret = rand::random::<JwtSecret>();
        let mut service = tower::ServiceBuilder::new()
            .layer(crate::ServerLayer(jwt_secret))
            .service_fn(handle);

        let status = service
            .ready()
            .await
            .unwrap()
            .call(Request::builder().uri("/").body("").unwrap())
            .await
            .unwrap()
            .status();

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "request did not have a token while endpoint expected one"
        );

        // client

        let auth_header = jwt_secret
            .to_bearer()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let status = service
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .uri("/")
                    .header(AUTHORIZATION, &auth_header)
                    .body("")
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();

        assert_eq!(
            status,
            StatusCode::OK,
            "request should extract the token correctly"
        );

        sleep(Duration::from_secs(CLAIM_EXPIRATION + 2)).await;

        let status = service
            .ready()
            .await
            .unwrap()
            .call(
                Request::builder()
                    .uri("/")
                    .header(AUTHORIZATION, &auth_header)
                    .body("")
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();

        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "The token's lifetime has expired"
        );
    }

    async fn jsonrpsee(
        addr: &str,
        jwt_secret: JwtSecret,
    ) -> (jsonrpsee::server::ServerHandle, impl ClientT) {
        let service_builder = tower::ServiceBuilder::new().layer(ServerLayer(jwt_secret));

        let mut module = RpcModule::new(());
        module.register_method("hello", |_, _| "hello").unwrap();

        let server = jsonrpsee::server::Server::builder()
            .set_http_middleware(service_builder)
            .build(addr)
            .await
            .unwrap()
            .start(module);

        let client = HttpClientBuilder::new()
            .set_http_middleware(tower::ServiceBuilder::new().layer(ClientLayer(jwt_secret)))
            .build(&format!("http://{addr}"))
            .unwrap();

        (server, client)
    }

    // Bash: curl -X POST http://<HOST>:<IP> -i -H "authorization: Bearer <TOKEN>"
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_client_jwt() {
        const ADDRESS: &str = "localhost:22024";
        let url = format!("http://{ADDRESS}");
        let jwt_secret = rand::random::<JwtSecret>();

        let (_server, client) = jsonrpsee(ADDRESS, jwt_secret).await;

        for _ in 0..1_800 {
            if reqwest::get(&url).await.is_ok() {
                break;
            }

            debug!("wating server");
            sleep(Duration::from_millis(100)).await
        }

        assert!(HttpClientBuilder::new()
            .build(&url)
            .unwrap()
            .request::<String, _>("hello", rpc_params![])
            .await
            .is_err());

        assert!(client
            .request::<String, _>("hello", rpc_params![])
            .await
            .is_ok());

        // = = =

        let status = reqwest::get(&url).await.unwrap().status();

        assert_eq!(
            status,
            reqwest::StatusCode::UNAUTHORIZED,
            "The token's lifetime has expired"
        );

        let auth_head = jwt_secret
            .to_bearer()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let status = reqwest::Client::new()
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, auth_head)
            .send()
            .await
            .unwrap()
            .status();

        assert_eq!(
            status,
            reqwest::StatusCode::METHOD_NOT_ALLOWED,
            "request should extract the token correctly"
        );
    }
}
