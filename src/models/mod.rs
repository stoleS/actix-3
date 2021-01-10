pub mod user;
pub mod invitation;
pub mod slim_user;

use diesel::{r2d2::ConnectionManager, PgConnection};

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
