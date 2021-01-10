use actix_identity::Identity;
use actix_web::{
    dev::Payload, error::BlockingError, web, FromRequest, HttpRequest, HttpResponse,
};
use diesel::prelude::*;
use diesel::PgConnection;
use futures::future::{ready, BoxFuture};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::{slim_user::SlimUser, user::User, Pool};
use crate::utils::errors::ServiceError;
use crate::utils::hash::{generate_jwt, verify, verify_jwt};

#[derive(Debug, Deserialize)]
pub struct AuthData {
    pub email: String,
    pub password: String,
}
#[derive(Serialize, Deserialize)]
pub struct AuthenticatedUser(pub Uuid);

impl FromRequest for AuthenticatedUser {
    type Config = ();
    type Error = ServiceError;
    type Future = BoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, pl: &mut Payload) -> Self::Future {
        let identity = Identity::from_request(req, pl).into_inner();
        match identity {
            Ok(idt) => {
                let jwt = idt.identity().unwrap();
                let future = async move {
                    let token = verify_jwt(jwt.to_string())
                        .await
                        .map(|data| data.claims.sub)
                        .map_err(|err| {
                            dbg!(err);
                            ServiceError::Unauthorized
                        })?;

                    Ok(AuthenticatedUser(token))
                };
                Box::pin(future)
            }
            _ => {
                let error = ready(Err(ServiceError::Unauthorized.into()));
                Box::pin(error)
            }
        }
    }
}

pub async fn logout(id: Identity) -> HttpResponse {
    id.forget();
    HttpResponse::Ok().finish()
}

pub async fn login(
    auth_data: web::Json<AuthData>,
    id: Identity,
    pool: web::Data<Pool>,
) -> Result<HttpResponse, ServiceError> {
    let res = web::block(move || query(auth_data.into_inner(), pool)).await;

    match res {
        Ok(user) => {
            let jwt = generate_jwt(user.id).await?;
            id.remember(jwt);
            Ok(HttpResponse::Ok().finish())
        }
        Err(err) => match err {
            BlockingError::Error(service_error) => Err(service_error),
            BlockingError::Canceled => Err(ServiceError::InternalServerError),
        },
    }
}

pub async fn get_me(logged_user: AuthenticatedUser) -> HttpResponse {
    HttpResponse::Ok().json(logged_user)
}
/// Diesel query
fn query(auth_data: AuthData, pool: web::Data<Pool>) -> Result<SlimUser, ServiceError> {
    use crate::schema::users::dsl::{email, users};
    let conn: &PgConnection = &pool.get().unwrap();
    let mut items = users
        .filter(email.eq(&auth_data.email))
        .load::<User>(conn)?;

    if let Some(user) = items.pop() {
        if let Ok(matching) = verify(&user.hash, &auth_data.password) {
            if matching {
                return Ok(user.into());
            }
        }
    }
    Err(ServiceError::Unauthorized)
}
