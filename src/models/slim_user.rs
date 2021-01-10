use super::user::User;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct SlimUser {
  pub id: Uuid,
  pub username: String,
  pub email: String,
}

impl From<User> for SlimUser {
  fn from(user: User) -> Self {
      SlimUser { 
        id: user.id,
        username: user.username, 
        email: user.email,
      }
  }
}