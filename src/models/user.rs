use crate::schema::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Queryable, Insertable)]
#[table_name = "users"]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub hash: String,
    pub created_at: chrono::NaiveDateTime,
}

impl User {
    pub fn from_details<S: Into<String>, T: Into<String>>(username: S, email: S, pwd: T) -> Self {
        User {
            id: uuid::Uuid::new_v4(),
            username: username.into(),
            email: email.into(),
            hash: pwd.into(),
            created_at: chrono::Local::now().naive_local(),
        }
    }
}
