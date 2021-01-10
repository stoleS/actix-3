use super::errors::ServiceError;
use actix_web::web::block;
use argon2::{self, Config};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

lazy_static::lazy_static! {
    pub static ref SECRET_KEY: String = std::env::var("SECRET_KEY").unwrap_or_else(|_| "local_only_key".repeat(4));
    pub static ref JWT_KEY: String = std::env::var("JWT_KEY").unwrap_or_else(|_| "local_only_jwt".repeat(4));
}

const SALT: &'static [u8] = b"supersecuresalt";

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: i64,
}

pub fn hash_password(password: &str) -> Result<String, ServiceError> {
    let config = Config {
        secret: SECRET_KEY.as_bytes(),
        ..Default::default()
    };
    argon2::hash_encoded(password.as_bytes(), &SALT, &config).map_err(|err| {
        dbg!(err);
        ServiceError::InternalServerError
    })
}

pub fn verify(hash: &str, password: &str) -> Result<bool, ServiceError> {
    argon2::verify_encoded_ext(hash, password.as_bytes(), SECRET_KEY.as_bytes(), &[]).map_err(
        |err| {
            dbg!(err);
            ServiceError::Unauthorized
        },
    )
}

pub async fn generate_jwt(user_id: Uuid) -> Result<String, ServiceError> {
    let jwt_key = JWT_KEY.clone();
    block(move || {
        let headers = Header::default();
        let encoding_key = EncodingKey::from_secret(jwt_key.as_bytes());
        let now = Utc::now() + Duration::days(1); // Expires in 1 day
        let claims = Claims {
            sub: user_id,
            exp: now.timestamp(),
        };
        encode(&headers, &claims, &encoding_key)
    })
    .await
    .map_err(|err| {
        dbg!(err);
        ServiceError::InternalServerError
    })
}

pub async fn verify_jwt(token: String) -> Result<TokenData<Claims>, ServiceError> {
    let jwt_key = JWT_KEY.clone();
    block(move || {
        let decoding_key = DecodingKey::from_secret(jwt_key.as_bytes());
        let validation = Validation::default();
        decode::<Claims>(&token, &decoding_key, &validation)
    })
    .await
    .map_err(|err| {
        dbg!(err);
        ServiceError::InternalServerError
    })
}
