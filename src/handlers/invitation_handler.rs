use actix_web::{error::BlockingError, web, HttpResponse};
use diesel::{prelude::*, PgConnection};
use serde::Deserialize;

use crate::services::{email_service::send_invitation};
use crate::utils::{ errors::ServiceError };
use crate::models::{invitation::Invitation, Pool};

#[derive(Deserialize)]
pub struct InvitationData {
    pub email: String,
}

pub async fn post_invitation(
  invitation_data: web::Json<InvitationData>,
  pool: web::Data<Pool>,
) -> Result<HttpResponse, ServiceError> {
  let res = web::block(move || create_invitation(invitation_data.into_inner().email, pool)).await;

  match res {
      Ok(_) => Ok(HttpResponse::Ok().finish()),
      Err(err) => match err {
          BlockingError::Error(service_error) => Err(service_error),
          BlockingError::Canceled => Err(ServiceError::InternalServerError),
      },
  }
}

fn create_invitation(
  eml: String,
  pool: web::Data<Pool>,
) -> Result<(), ServiceError> {
  let invitation = dbg!(query(eml, pool)?);
  send_invitation(&invitation)
}

fn query(eml: String, pool: web::Data<Pool>) -> Result<Invitation, ServiceError> {
  use crate::schema::invitations::dsl::invitations;

  let new_invitation: Invitation = eml.into();
  let conn: &PgConnection = &pool.get().unwrap();

  let inserted_invitation = diesel::insert_into(invitations)
      .values(&new_invitation)
      .get_result(conn)?;

  Ok(inserted_invitation)
}